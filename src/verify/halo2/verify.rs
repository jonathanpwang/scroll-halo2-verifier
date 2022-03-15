use super::{lookup, permutation, vanish};
use crate::arith::api::{ContextGroup, ContextRing};
use crate::arith::code::{FieldCode, PointCode};
use crate::schema::ast::{ArrayOpAdd, CommitQuery, MultiOpenProof, SchemaItem};
use crate::schema::utils::{RingUtils, VerifySetupHelper};
use crate::schema::{EvaluationProof, EvaluationQuery, SchemaGenerator};
use crate::verify::halo2::permutation::Evaluated;
use crate::verify::halo2::permutation::EvaluatedSet;
use crate::{arith_in_ctx, infix2postfix};
use crate::{commit, scalar};
use group::Curve;
use halo2_proofs::arithmetic::{CurveAffine, Engine, Field, FieldExt, MultiMillerLoop};
use halo2_proofs::plonk::{Error, Expression, VerifyingKey};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::poly::EvaluationDomain;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::ChallengeScalar;
use halo2_proofs::transcript::{read_n_points, read_n_scalars, EncodedChallenge, TranscriptRead};
use pairing_bn256::bn256::G1Affine;
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

pub struct PlonkCommonSetup {
    pub l: u32,
    pub n: u32,
}

pub trait Evaluable<
    C,
    S,
    T,
    Error: Debug,
    SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
>
{
    fn ctx_evaluate(
        &self,
        sgate: &SGate,
        ctx: &mut C,
        fixed: &impl Fn(usize) -> S,
        advice: &impl Fn(usize) -> S,
        instance: &impl Fn(usize) -> S,
    ) -> S;
}

impl<
        C,
        S: Clone,
        T: FieldExt,
        Error: Debug,
        SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
    > Evaluable<C, S, T, Error, SGate> for Expression<S>
{
    fn ctx_evaluate(
        &self,
        sgate: &SGate,
        ctx: &mut C,
        fixed: &impl Fn(usize) -> S,
        advice: &impl Fn(usize) -> S,
        instance: &impl Fn(usize) -> S,
    ) -> S {
        match self {
            Expression::Constant(scalar) => scalar.clone(),
            Expression::Selector(selector) => {
                panic!("virtual selectors are removed during optimization")
            }
            Expression::Fixed {
                query_index,
                column_index,
                rotation,
            } => fixed(*query_index),
            Expression::Advice {
                query_index,
                column_index,
                rotation,
            } => advice(*query_index),
            Expression::Instance {
                query_index,
                column_index,
                rotation,
            } => instance(*query_index),
            Expression::Negated(a) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                let zero = &sgate.zero(ctx).unwrap();
                arith_in_ctx!([sgate, ctx] zero - a).unwrap()
            }
            Expression::Sum(a, b) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                let b = &b.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                arith_in_ctx!([sgate, ctx] a + b).unwrap()
            }
            Expression::Product(a, b) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                let b = &b.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                arith_in_ctx!([sgate, ctx] a * b).unwrap()
            }
            Expression::Scaled(a, f) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                arith_in_ctx!([sgate, ctx] f * a).unwrap()
            }
        }
    }
}

pub struct VerifierParams<C, S: Clone, P: Clone, Error: Debug> {
    //public_wit: Vec<C::ScalarExt>,
    pub gates: Vec<Vec<Expression<S>>>,
    pub common: PlonkCommonSetup,
    pub lookup_evaluated: Vec<Vec<lookup::Evaluated<C, S, P, Error>>>,
    pub permutation_evaluated: Vec<permutation::Evaluated<C, S, P, Error>>,
    pub instance_commitments: Vec<Vec<P>>,
    pub instance_evals: Vec<Vec<S>>,
    pub instance_queries: Vec<(usize, i32)>,
    pub advice_commitments: Vec<Vec<P>>,
    pub advice_evals: Vec<Vec<S>>,
    pub advice_queries: Vec<(usize, i32)>,
    pub fixed_commitments: Vec<P>,
    pub fixed_evals: Vec<S>,
    pub fixed_queries: Vec<(usize, i32)>,
    pub permutation_commitments: Vec<P>,
    pub permutation_evals: Vec<S>, // permutations common evaluation
    pub vanish_commitments: Vec<P>,
    pub random_commitment: P,
    pub random_eval: S,
    pub beta: S,
    pub gamma: S,
    pub theta: S,
    pub delta: S,
    pub x: S,
    pub u: S,
    pub v: S,
    pub xi: S,
    pub omega: S,
    pub _ctx: PhantomData<C>,
    pub _error: PhantomData<Error>,
}

pub(crate) trait IVerifierParams<
    'a,
    C: Clone,
    S: Clone,
    T: FieldExt,
    P: Clone,
    Error: Debug,
    SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
>
{
    fn rotate_omega(&self, sgate: &'a SGate, ctx: &'a mut C, at: i32) -> Result<S, Error>;
    fn x_next(&'a self, sgate: &'a SGate, ctx: &'a mut C) -> Result<S, Error>;
    fn x_last(&'a self, sgate: &'a SGate, ctx: &'a mut C) -> Result<S, Error>;
    fn queries(
        &'a self,
        sgate: &'a SGate,
        ctx: &'a mut C,
        y: &'a S,
        w: &'a S,
        l: u32, // blind_factors + 1
    ) -> Result<Vec<EvaluationProof<'a, S, P>>, Error>;
}

impl<
        'a,
        C: Clone,
        S: Clone,
        T: FieldExt,
        P: Clone,
        Error: Debug,
        SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
    > IVerifierParams<'a, C, S, T, P, Error, SGate> for VerifierParams<C, S, P, Error>
{
    fn rotate_omega(&self, sgate: &'a SGate, ctx: &'a mut C, at: i32) -> Result<S, Error> {
        unimplemented!("rotate omega")
    }

    fn x_next(&'a self, sgate: &'a SGate, ctx: &'a mut C) -> Result<S, Error> {
        let x = &self.x;
        let omega = &self.omega;
        arith_in_ctx!([sgate, ctx] x * omega)
    }

    fn x_last(&'a self, sgate: &'a SGate, ctx: &'a mut C) -> Result<S, Error> {
        let x = &self.x;
        let omega = &self.omega;
        self.rotate_omega(sgate, ctx, -(self.common.l as i32))
    }

    fn queries(
        &'a self,
        sgate: &'a SGate,
        ctx: &'a mut C,
        y: &'a S,
        w: &'a S,
        l: u32, // blind_factors + 1
    ) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        let zero = &sgate.zero(ctx);
        let omega = &self.omega;
        let x = &self.x;
        let x_next = &self.x_next(sgate, ctx)?;
        let x_last = &self.x_last(sgate, ctx)?;
        let x_inv = &arith_in_ctx!([sgate, ctx] x / omega)?;
        let xn = &self.rotate_omega(sgate, ctx, self.common.n as i32)?; // double check let xn = x.pow(&[params.n as u64, 0, 0, 0]);
        let ls = sgate.get_lagrange_commits(ctx, x, xn, w, self.common.n, l)?;
        let l_0 = &(ls[0]);
        let l_last = &ls[l as usize];
        let l_blind = &sgate.add_array(ctx, ls[1..(l as usize)].iter().collect())?;

        let pcommon = permutation::CommonEvaluated {
            permutation_evals: &self.permutation_evals,
            permutation_commitments: &self.permutation_commitments,
        };

        let mut expression = vec![];

        /* All calculation relies on ctx thus FnMut for map does not work anymore */
        for k in 0..self.advice_evals.len() {
            let advice_evals = &self.advice_evals[k];
            let instance_evals = &self.instance_evals[k];
            let permutation = &self.permutation_evaluated[k];
            let lookups = &self.lookup_evaluated[k];
            for i in 0..self.gates.len() {
                for j in 0..self.gates[i].len() {
                    let poly = &self.gates[i][j];
                    expression.push(poly.ctx_evaluate(
                        sgate,
                        ctx,
                        &|n| self.fixed_evals[n].clone(),
                        &|n| advice_evals[n].clone(),
                        &|n| instance_evals[n].clone(),
                    ));
                }
            }
            let p = permutation
                .expressions(
                    //vk,
                    //&vk.cs.permutation,
                    //&permutations_common,
                    //fixed_evals,
                    //advice_evals,
                    //instance_evals,
                    sgate,
                    ctx,
                    &pcommon,
                    l_0,
                    l_last,
                    l_blind,
                    &self.delta,
                    &self.beta,
                    &self.gamma,
                    x,
                )
                .unwrap();
            expression.extend(p);
            for i in 0..lookups.len() {
                let l = lookups[i]
                    .expressions(
                        sgate,
                        ctx,
                        &self.fixed_evals.iter().map(|ele| ele).collect(),
                        &advice_evals.iter().map(|ele| ele).collect(),
                        &instance_evals.iter().map(|ele| ele).collect(),
                        l_0,
                        l_last,
                        l_blind,
                        //argument,
                        &self.theta,
                        &self.beta,
                        &self.gamma,
                    )
                    .unwrap();
                expression.extend(l);
            }
        }

        let vanish = vanish::Evaluated::new(
            sgate,
            ctx,
            expression,
            y,
            xn,
            &self.random_commitment,
            &self.random_eval,
            self.vanish_commitments.iter().map(|ele| ele).collect(),
        );

        //vanishing.verify(expressions, y, xn)

        let queries = self
            .instance_commitments
            .iter()
            .zip(self.instance_evals.iter())
            .zip(self.advice_commitments.iter())
            .zip(self.advice_evals.iter())
            .zip(self.permutation_evaluated.iter())
            .zip(self.lookup_evaluated.iter())
            .flat_map(
                |(
                    (
                        (
                            ((instance_commitments, instance_evals), advice_commitments),
                            advice_evals,
                        ),
                        permutation,
                    ),
                    lookups,
                )| {
                    iter::empty()
                        .chain(self.instance_queries.iter().enumerate().map(
                            move |(query_index, &(column, at))| {
                                EvaluationQuery::new(
                                    self.rotate_omega(sgate, ctx, at).unwrap(),
                                    &instance_commitments[column],
                                    &instance_evals[query_index],
                                )
                            },
                        ))
                        .chain(self.advice_queries.iter().enumerate().map(
                            move |(query_index, &(column, at))| {
                                EvaluationQuery::new(
                                    self.rotate_omega(sgate, ctx, at).unwrap(),
                                    &advice_commitments[column],
                                    &advice_evals[query_index],
                                )
                            },
                        ))
                        .chain(permutation.queries(x_next, x_last)) // tested
                        .chain(
                            lookups
                                .iter()
                                .flat_map(move |p| p.queries(x, x_inv, x_next))
                                .into_iter(),
                        )
                },
            )
            .chain(
                self.fixed_queries
                    .iter()
                    .enumerate()
                    .map(|(query_index, &(column, at))| {
                        EvaluationQuery::<'a, S, P>::new(
                            self.rotate_omega(sgate, ctx, at).unwrap(),
                            &self.fixed_commitments[column],
                            &self.fixed_evals[query_index],
                        )
                    }),
            )
            .chain(pcommon.queries(x))
            .chain(vanish.queries(x));
        unimplemented!("get point schemas not implemented")
    }
}

impl<
        'a,
        C: Clone,
        S: Field,
        P: Clone,
        TS,
        TP,
        Error: Debug,
        SGate: ContextGroup<C, S, S, TS, Error> + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, TP, Error>,
    > SchemaGenerator<'a, C, S, P, TS, TP, Error, SGate, PGate> for VerifierParams<C, S, P, Error>
{
    fn get_point_schemas(
        &self,
        ctx: &mut C,
        sgate: &SGate,
        pgate: &PGate,
    ) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        unimplemented!("get point schemas not implemented")
    }

    fn batch_multi_open_proofs(
        &self,
        ctx: &mut C,
        sgate: &SGate,
        pgate: &PGate,
    ) -> Result<MultiOpenProof<'a, S, P>, Error> {
        let mut proofs = self.get_point_schemas(ctx, sgate, pgate)?;
        proofs.reverse();
        let (mut w_x, mut w_g) = {
            let s = &proofs[0].s;
            let w = CommitQuery {
                c: Some(proofs[0].w),
                v: None,
            };
            (
                commit!(w),
                scalar!(proofs[0].point) * commit!(w) + s.clone(),
            )
        };
        let _ = proofs[1..].iter().map(|p| {
            let s = &p.s;
            let w = CommitQuery {
                c: Some(p.w),
                v: None,
            };
            w_x = scalar!(self.u) * w_x.clone() + commit!(w);
            w_g = scalar!(self.u) * w_g.clone() + scalar!(p.point) * commit!(w) + s.clone();
        });
        Ok(MultiOpenProof { w_x, w_g })
    }
}

impl<'a, CTX, S: Clone, P: Clone, Error: Debug> VerifierParams<CTX, S, P, Error> {
    fn from_expression<
        C: MultiMillerLoop,
        SGate: ContextGroup<CTX, S, S, <C::G1Affine as CurveAffine>::ScalarExt, Error>
            + ContextRing<CTX, S, S, Error>,
        PGate: ContextGroup<CTX, S, P, C::G1Affine, Error>,
    >(
        sgate: &'a SGate,
        pgate: &'a PGate,
        ctx: &mut CTX,
        expr: Expression<<C::G1Affine as CurveAffine>::ScalarExt>,
    ) -> Result<Expression<S>, Error> {
        Ok(match expr {
            Expression::Constant(c) => Expression::Constant(sgate.from_constant(ctx, c)?),
            Expression::Selector(s) => Expression::Selector(s),
            Expression::Fixed {
                query_index,
                column_index,
                rotation,
            } => Expression::Fixed {
                query_index,
                column_index,
                rotation,
            },
            Expression::Advice {
                query_index,
                column_index,
                rotation,
            } => Expression::Advice {
                query_index,
                column_index,
                rotation,
            },
            Expression::Instance {
                query_index,
                column_index,
                rotation,
            } => Expression::Instance {
                query_index,
                column_index,
                rotation,
            },
            Expression::Negated(b) => {
                Expression::Negated(Box::<Expression<S>>::new(Self::from_expression::<
                    C,
                    SGate,
                    PGate,
                >(
                    sgate, pgate, ctx, *b
                )?))
            }
            Expression::Sum(b1, b2) => Expression::Sum(
                Box::<Expression<S>>::new(Self::from_expression::<C, SGate, PGate>(
                    sgate, pgate, ctx, *b1,
                )?),
                Box::<Expression<S>>::new(Self::from_expression::<C, SGate, PGate>(
                    sgate, pgate, ctx, *b2,
                )?),
            ),
            Expression::Product(b1, b2) => Expression::Product(
                Box::<Expression<S>>::new(Self::from_expression::<C, SGate, PGate>(
                    sgate, pgate, ctx, *b1,
                )?),
                Box::<Expression<S>>::new(Self::from_expression::<C, SGate, PGate>(
                    sgate, pgate, ctx, *b2,
                )?),
            ),
            Expression::Scaled(b, f) => Expression::Scaled(
                Box::<Expression<S>>::new(Self::from_expression::<C, SGate, PGate>(
                    sgate, pgate, ctx, *b,
                )?),
                sgate.from_constant(ctx, f)?,
            ),
        })
    }

    pub fn from_transcript<
        C: MultiMillerLoop,
        E: EncodedChallenge<C::G1Affine>,
        T: TranscriptRead<C::G1Affine, E>,
        SGate: ContextGroup<CTX, S, S, <C::G1Affine as CurveAffine>::ScalarExt, Error>
            + ContextRing<CTX, S, S, Error>,
        PGate: ContextGroup<CTX, S, P, C::G1Affine, Error>,
    >(
        sgate: &'a SGate,
        pgate: &'a PGate,
        ctx: &mut CTX,
        u: <C::G1Affine as CurveAffine>::ScalarExt,
        v: <C::G1Affine as CurveAffine>::ScalarExt,
        xi: <C::G1Affine as CurveAffine>::ScalarExt,
        instances: &[&[&[C::Scalar]]],
        vk: &VerifyingKey<C::G1Affine>,
        params: &ParamsVerifier<C>,
        transcript: &mut T,
    ) -> Result<VerifierParams<CTX, S, P, Error>, Error> {
        for instances in instances.iter() {
            assert!(instances.len() != vk.cs.num_instance_columns)
        }

        let instance_commitments = instances
            .iter()
            .map(|instance| {
                instance
                    .iter()
                    .map(|instance| {
                        assert!(instance.len() > params.n as usize - (vk.cs.blinding_factors() + 1));
                        Ok(params.commit_lagrange(instance.to_vec()).to_affine())
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let num_proofs = instance_commitments.len();

        // TODO: replace hash method and add it into circuits
        // Hash verification key into transcript
        vk.hash_into(transcript).unwrap();

        for instance_commitments in instance_commitments.iter() {
            // Hash the instance (external) commitments into the transcript
            for commitment in instance_commitments {
                transcript.common_point(*commitment).unwrap()
            }
        }

        let instance_commitments = instance_commitments
            .into_iter()
            .map(|instance| {
                instance
                    .into_iter()
                    .map(|instance| pgate.from_constant(ctx, instance))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let advice_commitments = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                // Hash the prover's advice commitments into the transcript
                let points = read_n_points(transcript, vk.cs.num_advice_columns).unwrap();
                points
                    .into_iter()
                    .map(|advice| pgate.from_constant(ctx, advice))
                    .collect()
            })
            .collect::<Result<Vec<_>, _>>()?;

        // TODO: Put hash process of theta into circuit
        // Sample theta challenge for keeping lookup columns linearly independent
        let theta: ChallengeScalar<<C as Engine>::G1Affine, T> =
            transcript.squeeze_challenge_scalar();
        let theta = sgate.from_constant(ctx, *theta)?;

        let lookups_permuted = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                // Hash each lookup permuted commitment
                vk.cs
                    .lookups
                    .iter()
                    .map(|argument| argument.read_permuted_commitments(transcript))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>().unwrap();

        // Sample beta challenge
        let beta: ChallengeScalar<<C as Engine>::G1Affine, T> =
            transcript.squeeze_challenge_scalar();
        let beta = sgate.from_constant(ctx, *beta)?;

        // Sample gamma challenge
        let gamma: ChallengeScalar<<C as Engine>::G1Affine, T> =
            transcript.squeeze_challenge_scalar();
        let gamma = sgate.from_constant(ctx, *gamma)?;

        let permutations_committed = (0..num_proofs)
            .map(|_| {
                // Hash each permutation product commitment
                vk.cs.permutation.read_product_commitments(vk, transcript)
            })
            .collect::<Result<Vec<_>, _>>().unwrap();

        let lookups_committed = lookups_permuted
            .into_iter()
            .map(|lookups| {
                // Hash each lookup product commitment
                lookups
                    .into_iter()
                    .map(|lookup| lookup.read_product_commitment(transcript))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>().unwrap();

        let random_poly_commitment = transcript.read_point().unwrap();
        let random_commitment = pgate.from_constant(ctx, random_poly_commitment)?;

        // Sample y challenge, which keeps the gates linearly independent.
        let y: ChallengeScalar<<C as Engine>::G1Affine, T> = transcript.squeeze_challenge_scalar();
        let y = sgate.from_constant(ctx, *y)?;

        let h_commitments = read_n_points(transcript, vk.domain.get_quotient_poly_degree()).unwrap();
        let h_commitments = h_commitments
            .iter()
            .map(|&affine| pgate.from_constant(ctx, affine))
            .collect::<Result<Vec<_>, _>>()?;

        // Sample x challenge, which is used to ensure the circuit is
        // satisfied with high probability.
        let x: ChallengeScalar<<C as Engine>::G1Affine, T> = transcript.squeeze_challenge_scalar();
        let x = sgate.from_constant(ctx, *x)?;

        let instance_evals = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                read_n_scalars(transcript, vk.cs.instance_queries.len()).unwrap()
                    .into_iter()
                    .map(|s| sgate.from_constant(ctx, s))
                    .collect()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let advice_evals = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                read_n_scalars(transcript, vk.cs.advice_queries.len()).unwrap()
                    .into_iter()
                    .map(|s| sgate.from_constant(ctx, s))
                    .collect()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let fixed_evals = read_n_scalars(transcript, vk.cs.fixed_queries.len()).unwrap()
            .into_iter()
            .map(|s| sgate.from_constant(ctx, s))
            .collect::<Result<Vec<_>, _>>()?;

        let random_eval = transcript.read_scalar().unwrap();
        let random_eval = sgate.from_constant(ctx, random_eval)?;

        let permutations_common = vk.permutation.evaluate(transcript).unwrap();

        let permutation_evaluated = permutations_committed
            .into_iter()
            .map(|permutation| permutation.evaluate(transcript))
            .collect::<Result<Vec<_>, _>>().unwrap();
        let permutation_evaluated_sets = permutation_evaluated
            .into_iter()
            .map(|permutation_evals| {
                Ok(permutation_evals
                    .sets
                    .iter()
                    .map(|eval| {
                        Ok(EvaluatedSet {
                            permutation_product_commitment: pgate
                                .from_constant(ctx, eval.permutation_product_commitment)?,
                            permutation_product_eval: sgate
                                .from_constant(ctx, eval.permutation_product_eval)?,
                            permutation_product_next_eval: sgate
                                .from_constant(ctx, eval.permutation_product_next_eval)?,
                            permutation_product_last_eval: eval
                                .permutation_product_last_eval
                                .map(|e| sgate.from_constant(ctx, e))
                                .transpose()?,
                            chunk_len: vk.cs.degree() - 2,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let permutation_evaluated_evals = advice_evals
            .iter()
            .zip(instance_evals.iter())
            .map(|(advice_evals, instance_evals)| {
                vk.cs
                    .permutation
                    .columns
                    .chunks(vk.cs.degree() - 2)
                    .map(|columns| {
                        columns
                            .iter()
                            .map(|column| match column.column_type() {
                                halo2_proofs::plonk::Any::Advice => {
                                    advice_evals
                                        [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                }
                                halo2_proofs::plonk::Any::Fixed => {
                                    fixed_evals[vk.cs.get_any_query_index(*column, Rotation::cur())]
                                }
                                halo2_proofs::plonk::Any::Instance => {
                                    instance_evals
                                        [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
                    .concat()
            })
            .collect::<Vec<_>>();

        let permutation_evaluated = permutation_evaluated_sets
            .into_iter()
            .zip(permutation_evaluated_evals.into_iter())
            .map(
                |(permutation_evaluated_set, permutation_evaluated_eval)| Evaluated {
                    x,
                    sets: permutation_evaluated_set,
                    evals: permutation_evaluated_eval,
                    chunk_len: vk.cs.degree() - 2,
                    _m: PhantomData,
                },
            )
            .collect();

        let lookup_evaluated = lookups_committed
            .into_iter()
            .map(|lookups| -> Result<Vec<_>, _> {
                lookups
                    .into_iter()
                    .map(|lookup| lookup.evaluate(transcript))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>().unwrap();

        let lookup_evaluated = lookup_evaluated
            .into_iter()
            .map(|vec| {
                vec.into_iter()
                    .zip(vk.cs.lookups.iter())
                    .map(|(lookup, argument)| {
                        Ok(crate::verify::halo2::lookup::Evaluated {
                            input_expressions: argument
                                .input_expressions
                                .iter()
                                .map(|expr| {
                                    Self::from_expression::<C, SGate, PGate>(
                                        sgate,
                                        pgate,
                                        ctx,
                                        expr.clone(),
                                    )
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                            table_expressions: argument
                                .table_expressions
                                .iter()
                                .map(|expr| {
                                    Self::from_expression::<C, SGate, PGate>(
                                        sgate,
                                        pgate,
                                        ctx,
                                        expr.clone(),
                                    )
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                            committed: crate::verify::halo2::lookup::Committed {
                                permuted: crate::verify::halo2::lookup::PermutationCommitments {
                                    permuted_input_commitment: pgate.from_constant(
                                        ctx,
                                        lookup.committed.permuted.permuted_input_commitment,
                                    )?,
                                    permuted_table_commitment: pgate.from_constant(
                                        ctx,
                                        lookup.committed.permuted.permuted_table_commitment,
                                    )?,
                                },
                                product_commitment: pgate
                                    .from_constant(ctx, lookup.committed.product_commitment)?,
                            },
                            product_eval: sgate.from_constant(ctx, lookup.product_eval)?,
                            product_next_eval: sgate
                                .from_constant(ctx, lookup.product_next_eval)?,
                            permuted_input_eval: sgate
                                .from_constant(ctx, lookup.permuted_input_eval)?,
                            permuted_input_inv_eval: sgate
                                .from_constant(ctx, lookup.permuted_input_inv_eval)?,
                            permuted_table_eval: sgate
                                .from_constant(ctx, lookup.permuted_table_eval)?,
                            _m: PhantomData,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let fixed_commitments = vk
            .fixed_commitments
            .iter()
            .map(|&affine| pgate.from_constant(ctx, affine))
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(VerifierParams::<CTX, S, P, Error> {
            gates: vk
                .cs
                .gates
                .iter()
                .map(|gate| {
                    gate.polys
                        .iter()
                        .map(|expr| {
                            Self::from_expression::<C, SGate, PGate>(
                                sgate,
                                pgate,
                                ctx,
                                expr.clone(),
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()
                })
                .collect::<Result<Vec<_>, Error>>()?,
            common: PlonkCommonSetup {
                l: vk.cs.blinding_factors() as u32 + 1,
                n: (params.n as u32),
            },
            lookup_evaluated,
            permutation_evaluated,
            instance_commitments,
            instance_evals,
            instance_queries: vk
                .cs
                .instance_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            advice_commitments,
            advice_evals,
            advice_queries: vk
                .cs
                .advice_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            fixed_commitments,
            fixed_evals,
            fixed_queries: vk
                .cs
                .fixed_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            permutation_commitments: vk
                .permutation
                .commitments
                .iter()
                .map(|commit| pgate.from_constant(ctx, *commit))
                .collect::<Result<Vec<_>, Error>>()?,
            permutation_evals: permutations_common
                .permutation_evals
                .into_iter()
                .map(|s| sgate.from_constant(ctx, s))
                .collect::<Result<Vec<_>, Error>>()?,
            vanish_commitments: h_commitments.iter().map(|&elem| elem).collect(),
            random_commitment: pgate.from_constant(ctx, random_poly_commitment)?,
            random_eval,
            beta,
            gamma,
            theta,
            delta: sgate.from_constant(
                ctx,
                <<C::G1Affine as CurveAffine>::ScalarExt as FieldExt>::DELTA,
            )?,
            x,
            u: sgate.from_constant(ctx, u)?,
            v: sgate.from_constant(ctx, v)?,
            xi: sgate.from_constant(ctx, xi)?,
            omega: sgate.from_constant(ctx, vk.domain.get_omega())?,
            _ctx: PhantomData,
            _error: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Evaluable;
    use crate::{arith::code::FieldCode, verify::halo2::test::build_verifier_params};
    use pairing_bn256::bn256::Fr;

    #[test]
    fn test_ctx_evaluate() {
        let sgate = FieldCode::<Fr> {
            one: Fr::one(),
            zero: Fr::zero(),
            generator: Fr::one(),
        };

        let params = build_verifier_params().unwrap();

        params
            .advice_evals
            .iter()
            .zip(params.instance_evals.iter())
            .for_each(|(advice_evals, instance_evals)| {
                params.gates.iter().for_each(|gate| {
                    gate.iter().for_each(|poly| {
                        let res = poly.ctx_evaluate(
                            &sgate,
                            &mut (),
                            &|n| params.fixed_evals[n],
                            &|n| advice_evals[n],
                            &|n| instance_evals[n],
                        );
                        let expected = poly.evaluate(
                            &|scalar| scalar,
                            &|_| panic!("virtual selectors are removed during optimization"),
                            &|n, _, _| params.fixed_evals[n],
                            &|n, _, _| advice_evals[n],
                            &|n, _, _| instance_evals[n],
                            &|a| -a,
                            &|a, b| a + &b,
                            &|a, b| a * &b,
                            &|a, scalar| a * &scalar,
                        );
                        assert_eq!(res, expected);
                    })
                })
            });
    }
}
