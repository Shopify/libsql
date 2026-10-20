// Repro for tursodatabase/libsql#2251: dropping a local connection closed the
// sqlite3 handle twice (LibsqlConnection::drop, then the inner
// Connection::drop). The second sqlite3_close_v2 read freed memory.
//
// Run under a guard allocator so the use-after-free faults on the first
// iteration instead of depending on allocator reuse:
//
//   cargo build -p libsql --example double_close_repro --features replication
//   DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib \
//       ./target/debug/examples/double_close_repro   # macOS
//   valgrind ./target/debug/examples/double_close_repro   # Linux
//
// Without the fix: SIGSEGV in sqlite3SafetyCheckSickOrOk (sqlite3.c:36835).
// With the fix: prints "no crash".
#[tokio::main]
async fn main() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("repro.db");
    for i in 0..20 {
        let db = libsql::Builder::new_local(path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let conn = db.connect().unwrap();
        conn.execute("CREATE TABLE IF NOT EXISTS t(x INTEGER)", ())
            .await
            .unwrap();
        drop(conn);
        drop(db);
        println!("iteration {i} ok");
    }
    println!("no crash");
}
