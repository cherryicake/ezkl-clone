use std::{sync::Mutex, time::Instant};

use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use ezkl::verified_model_session::VerifiedModel;
use log::info;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
struct ProveQuery {
    model: Vec<i32>,
    inputs: Vec<f64>,
}

#[derive(Serialize, Debug)]
struct ProveResponse {
    query_output: String,
}

#[post("/zkproof")]
async fn proof(
    query_input: web::Json<ProveQuery>,
    verified_models: web::Data<Mutex<Vec<VerifiedModel>>>,
) -> impl Responder {
    info!("Generating input file: {:?}", query_input.0);
    let start = Instant::now();
    let verified_model = match verified_models.lock().map(|mut vs| vs.pop()) {
        Ok(Some(verified_model)) => verified_model,
        _ => VerifiedModel::new(),
    };
    let output = verified_model
        .gen_proof(query_input.inputs.to_owned())
        .await
        .unwrap();
    if let Ok(mut verified_models) = verified_models.lock() {
        verified_models.push(verified_model);
        info!(
            "EZKL proof success, verified_models: {}  elapsed time: {:?} ✅",
            verified_models.len(),
            start.elapsed()
        );
    }

    return HttpResponse::Ok().json(ProveResponse {
        query_output: output,
    });
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    log4rs::init_file("config/log4rs.yaml", Default::default()).unwrap();
    let verified_models = web::Data::new(Mutex::new(vec![VerifiedModel::new()]));
    HttpServer::new(move || App::new().app_data(verified_models.clone()).service(proof))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
