use actix_web::{get, post, web, App, HttpResponse, HttpServer};
use actix_web::http::header::{self, HeaderValue};
use actix_web::HttpRequest;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use chrono::{Duration, Utc};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    email: String,
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<usize>,
}

#[get("/")]
async fn hello_world() -> HttpResponse {
    HttpResponse::Ok().json(json!({"hello": "world"}))
}

#[post("/login")]
async fn login(req: web::Json<Claims>) -> HttpResponse {
    let secret = "supersecret".as_bytes();
    let expiration = Utc::now() + Duration::hours(1);

    let access_token = encode(
        &Header::default(),
        &Claims {
            email: req.email.clone(),
            password: req.password.clone(),
            exp: Some(expiration.timestamp() as usize),
        },
        &EncodingKey::from_secret(secret),
    )
    .unwrap();

    let refresh_token = encode(
        &Header::default(),
        &Claims {
            email: req.email.clone(),
            password: req.password.clone(),
            exp: Some(expiration.timestamp() as usize),
        },
        &EncodingKey::from_secret(secret),
    )
    .unwrap();

    HttpResponse::Ok()
        .append_header((header::SET_COOKIE, HeaderValue::from_str(&format!("dp_access_token={}", access_token)).unwrap()))
        .append_header((header::SET_COOKIE, HeaderValue::from_str(&format!("dp_refresh_token={}", refresh_token)).unwrap()))
        .json(json!({
            "dp_access_token": access_token,
            "dp_refresh_token": refresh_token,
        }))
}

#[post("/refresh")]
async fn refresh(req: HttpRequest) -> HttpResponse {
    let secret = "supersecret".as_bytes();
    let refresh_token = req
        .headers()
        .get("dp_refresh_token")
        .and_then(|header_value| header_value.to_str().ok())
        .unwrap_or("");

    let token_data = decode::<Claims>(
        refresh_token,
        &DecodingKey::from_secret(secret),
        &Validation::new(Algorithm::default()),
    )
    .ok();

    if let Some(token) = token_data {
        let expiration = Utc::now() + Duration::hours(1);

        let new_access_token = encode(
            &Header::default(),
            &Claims {
                email: token.claims.email.clone(),
                password: token.claims.password.clone(),
                exp: Some(expiration.timestamp() as usize),
            },
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let new_refresh_token = encode(
            &Header::default(),
            &Claims {
                email: token.claims.email,
                password: token.claims.password,
                exp: Some(expiration.timestamp() as usize),
            },
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        HttpResponse::Ok()
            .append_header((header::SET_COOKIE, HeaderValue::from_str(&format!("dp_access_token={}", new_access_token)).unwrap()))
            .append_header((header::SET_COOKIE, HeaderValue::from_str(&format!("dp_refresh_token={}", new_refresh_token)).unwrap()))
            .json(json!({
                "new_dp_access_token": new_access_token,
                "new_dp_refresh_token": new_refresh_token,
            }))
    } else {
        HttpResponse::BadRequest().finish()
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(hello_world)
            .service(login)
            .service(refresh)
    })
    .bind("0.0.0.0:8000")?
    .run()
    .await
}
