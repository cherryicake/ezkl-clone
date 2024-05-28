use std::{env, error::Error};

use std::cell::RefCell;

use halo2_proofs::plonk::{Circuit, ProvingKey, VerifyingKey};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy as KZGSingleStrategy;
use halo2curves::bn256::{Bn256, G1Affine};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;

use crate::circuit::CheckMode;
use crate::execute::load_params_prover;
use crate::pfsys::{create_proof_circuit, load_pk, ProofSplitCommit, ProofType};
use crate::Commitments;
use crate::{
    graph::{input::GraphData, GraphCircuit, GraphWitness},
    pfsys::load_vk,
};

///
#[derive(Debug)]
pub struct VerifiedModel {
    circuit: RefCell<GraphCircuit>,
    vk: Option<VerifyingKey<G1Affine>>,
    pk: ProvingKey<G1Affine>,
    params: ParamsKZG<Bn256>,
}

/// 模型验证
impl VerifiedModel {
    ///
    pub fn new() -> Self {
        let current_dir = env::current_dir().unwrap();
        let model_id = 0;
        let pk_path = current_dir.join(format!("deployment_layer/model_{model_id}/pk.key"));
        let vk_path = current_dir.join(format!("deployment_layer/model_{model_id}/vk.key"));
        let srs_path = current_dir.join(format!("deployment_layer/model_{model_id}/kzg.srs"));
        let circuit_path = current_dir.join(format!(
            "deployment_layer/model_{model_id}/model.compiled.json"
        ));
        // let settings_path = current_dir.join(format!("deployment_layer/model_{model_id}/settings.json"));
        // let sample_input_path = current_dir.join(format!("deployment_layer/model_{model_id}/input.json"));

        let circuit: GraphCircuit = GraphCircuit::load(circuit_path).unwrap();
        let settings = circuit.settings().clone();
        let logrows = settings.run_args.logrows;

        let vk: Option<VerifyingKey<halo2curves::bn256::G1Affine>> =
            Some(load_vk::<KZGCommitmentScheme<Bn256>, GraphCircuit>(vk_path, settings).unwrap());

        let pk =
            load_pk::<KZGCommitmentScheme<Bn256>, GraphCircuit>(pk_path, circuit.params()).unwrap();
        let params = load_params_prover::<KZGCommitmentScheme<Bn256>>(
            Some(srs_path),
            logrows,
            Commitments::KZG,
        )
        .unwrap();

        Self {
            circuit: RefCell::new(circuit),
            vk,
            pk,
            params,
        }
    }
    ///
    async fn gen_witness(&self, prove_query: Vec<f64>) -> Result<GraphWitness, Box<dyn Error>> {
        let data = GraphData::new(vec![prove_query].into());
        let mut input = self.circuit.borrow_mut().load_graph_input(&data).await?;
        let _settings = self.circuit.borrow().settings();
        let witness = self
            .circuit
            .borrow()
            .forward::<KZGCommitmentScheme<Bn256>>(
                &mut input,
                self.vk.as_ref(),
                None,
                true,
                true,
            )?;
        Ok(witness)
    }
    ///
    pub async fn gen_proof(&self, prove_query: Vec<f64>) -> Result<String, Box<dyn Error>> {
        let witness = self.gen_witness(prove_query).await?;
        self.circuit.borrow_mut().load_graph_witness(&witness)?;
        let pretty_public_inputs = self.circuit.borrow().pretty_public_inputs(&witness)?;
        let public_inputs = self.circuit.borrow().prepare_public_inputs(&witness)?;

        let commitment = self.circuit.borrow().settings().run_args.commitment.into();
        let proof_split_commits: Option<ProofSplitCommit> = witness.into();

        let mut snark = create_proof_circuit::<
            KZGCommitmentScheme<Bn256>,
            _,
            ProverSHPLONK<_>,
            VerifierSHPLONK<_>,
            KZGSingleStrategy<_>,
            _,
            EvmTranscript<_, _, _, _>,
            EvmTranscript<_, _, _, _>,
        >(
            self.circuit.borrow().clone(),
            vec![public_inputs],
            &self.params,
            &self.pk,
            CheckMode::SAFE,
            commitment,
            ProofType::Single.into(),
            proof_split_commits,
            None,
        )?;
        snark.pretty_public_inputs = pretty_public_inputs;
        Ok(serde_json::to_string(&snark)?)
    }
}

#[cfg(test)]
mod tests {
    use super::VerifiedModel;
    #[tokio::test]
    async fn test() {
        let prove_query = vec![
            -0.3367333979146827,
            0.6298721362647295,
            -0.07219390757178101,
            -0.06458135109190843,
            -0.7423325926995081,
        ];
        let session = VerifiedModel::new();
        let proof = session.gen_proof(prove_query).await.unwrap();
        println!("proof: \n {}", proof);
    }
}
