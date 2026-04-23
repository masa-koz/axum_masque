use rand::Rng;
use std::net::IpAddr;
use tokio_rusqlite::{Connection, OptionalExtension, Result as SqlResult, params};

#[derive(Debug, Clone)]
pub struct Store {
    conn: Connection,
}

impl Store {
    pub async fn new(path: &str, public_ip: IpAddr) -> SqlResult<Self> {
        let conn = Connection::open(path).await?;
        conn.call(move |conn| {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS public_addresses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sub TEXT,
                    addr TEXT NOT NULL
                )",
                params![],
            )?;
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM public_addresses", params![], |row| {
                    row.get(0)
                })?;
            if count == 0 {
                for port in 10000u16..20000u16 {
                    let addr = format!("{}:{}", public_ip, port);
                    conn.execute(
                        "INSERT INTO public_addresses (sub, addr) VALUES (?1, ?2)",
                        params!["__open__", addr],
                    )?;
                }
            }
            Ok(())
        })
        .await?;
        Ok(Self { conn })
    }

    pub async fn get(&self, sub: &str) -> SqlResult<Option<String>> {
        let conn = self.conn.clone();
        let sub = sub.to_string();
        Ok(conn
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT addr FROM public_addresses WHERE sub = ?1")?;
                stmt.query_row(params![sub], |row| Ok(row.get::<_, String>(0)?))
                    .optional()
            })
            .await?)
    }

    pub async fn assign(&self, sub: &str) -> SqlResult<Option<String>> {
        let conn = self.conn.clone();
        let sub = sub.to_string();
        Ok(conn
            .call(move |conn| {
                let open_count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM public_addresses WHERE sub = '__open__'",
                    params![],
                    |row| row.get(0),
                )?;
                if open_count == 0 {
                    return Ok(None);
                }

                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM public_addresses", params![], |row| {
                        row.get(0)
                    })?;

                let mut rng = rand::thread_rng();
                let mut stmt = conn.prepare(
                    "SELECT addr FROM public_addresses WHERE sub = '__open__' AND id = ?1",
                )?;
                let (id, addr) = loop {
                    let search_id = rng.gen_range(1..=count);
                    let res = stmt
                        .query_row(params![search_id], |row| {
                            Ok((search_id, row.get::<_, String>(0)?))
                        })
                        .optional()?;
                    if res.is_some() {
                        break res.unwrap();
                    }
                };
                conn.execute(
                    "UPDATE public_addresses SET sub = ?1 WHERE id = ?2",
                    params![sub, id],
                )?;
                Ok(Some(addr))
            })
            .await?)
    }
}
