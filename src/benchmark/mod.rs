mod benchmark;
mod benchmark_result;
pub mod delegation_benchmark;
mod our_benchmark;
mod pjvs_benchmark;
mod sdjwt_benchmark;

#[cfg(feature = "efficient")]
mod our_efficient_benchmark;
#[cfg(feature = "efficient")]
mod sdjwt_efficient_benchmark;
