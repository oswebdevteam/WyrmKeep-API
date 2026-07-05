pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod models;
pub mod routes;
pub mod services;
pub mod state;

#[cfg(test)]
mod tests {
    #[path = "../services/pattern_tests.rs"]
    mod pattern_tests;
    #[path = "../services/pipeline_tests.rs"]
    mod pipeline_tests;
}
