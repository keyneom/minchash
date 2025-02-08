use criterion::{black_box, criterion_group, criterion_main, Criterion};
use minchash::{SecureMultisetHash, FastMultisetHash};

fn benchmark_add_individual(c: &mut Criterion) {
    let elements: Vec<String> = (0..10_000).map(|i| format!("item{}", i)).collect();

    c.bench_function("Secure add elements individually", |b| {
        b.iter(|| {
            let mut ms = SecureMultisetHash::new();
            for elem in &elements {
                ms.add(black_box(elem.as_bytes()));
            }
        })
    });
}

fn benchmark_add_elements_parallel(c: &mut Criterion) {
    let elements: Vec<String> = (0..10_000).map(|i| format!("item{}", i)).collect();

    c.bench_function("Secure add elements in parallel", |b| {
        b.iter(|| {
            let mut ms = SecureMultisetHash::new();
            ms.add_elements(&elements);
        })
    });
}


fn benchmark_add_individual_fast(c: &mut Criterion) {
    let elements: Vec<String> = (0..10_000_000).map(|i| format!("item{}", i)).collect();

    c.bench_function("Fast add elements individually", |b| {
        b.iter(|| {
            let mut ms = FastMultisetHash::new();
            for elem in &elements {
                ms.add(black_box(elem.as_bytes()));
            }
        })
    });
}


fn benchmark_add_elements_parallel_fast(c: &mut Criterion) {
    let elements: Vec<String> = (0..10_000_000).map(|i| format!("item{}", i)).collect();

    c.bench_function("Fast add elements in parallel", |b| {
        b.iter(|| {
            let mut ms = FastMultisetHash::new();
            ms.add_elements(&elements);
        })
    });
}


criterion_group!(benches, benchmark_add_individual, benchmark_add_elements_parallel,
    benchmark_add_individual_fast, benchmark_add_elements_parallel_fast);
criterion_main!(benches);
