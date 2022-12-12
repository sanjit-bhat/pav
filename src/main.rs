#[macro_use] extern crate rocket;

use std::path::Path;
use rocket::tokio::fs::File;
use rocket::data::{Data, ToByteUnit};
use rocket::http::uri::Absolute;

#[get("/")]
fn index() -> &'static str {
    "
    USAGE

        POST /
            
            accepts raw data in body of request
            and responds with a link.
        
        GET /<id>

            retrieves content for paste with id `<id>`
    "
}

#[get("/<id>")]
async fn retrieve(id: &str) -> Option<File> {
    let upload_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/", "upload");
    let filename = Path::new(upload_dir).join(id);
    File::open(&filename).await.ok()
}

const HOST: Absolute<'static> = uri!("http://localhost:8000/upload");

#[post("/<id>", data = "<paste>")]
async fn upload(id: &str, paste: Data<'_>) -> std::io::Result<String> {
    let upload_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/", "upload");
    let filename = Path::new(upload_dir).join(id);
    paste.open(128.kibibytes()).into_file(&filename).await?;
    Ok(uri!(HOST, retrieve(id)).to_string())
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, retrieve, upload])
}
