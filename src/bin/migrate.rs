use sqlx::postgres::PgPoolOptions;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pool = PgPoolOptions::new().connect(&db_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    println!("Migrations applied successfully.");
    Ok(())
}
