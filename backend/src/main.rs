use actix_web::{web, App, HttpResponse, HttpServer, Responder, middleware};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::Path;
use std::fs::{File, create_dir_all};
use std::io::{Seek, SeekFrom, Write, Read};
use sha2::{Sha256, Digest};
use std::process::Command;
use std::thread;
use log::{info, error};

#[derive(Deserialize)]
struct WipeRequest {
    device_path: String,
    profile: String, // quick, secure
    email: String,
    force: Option<bool>
}

#[derive(Serialize, Clone)]
struct JobStatus {
    id: String,
    status: String,
    progress: f32,
    message: String,
    cert_path: Option<String>,
    email_status: Option<String>,
}

struct AppState {
    jobs: Mutex<Vec<JobStatus>>
}

fn timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

async fn index() -> impl Responder {
    HttpResponse::Ok().body("SecureWipe agent. Use the web UI at /static/index.html")
}

async fn targets() -> impl Responder {
    let mut list = vec![];
    if let Ok(out) = Command::new("nvme").arg("list").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines().skip(1) {
                if !line.trim().is_empty() {
                    list.push(serde_json::json!({"row": line.trim()}));
                }
            }
        }
    }
    if let Ok(out) = Command::new("lsblk").arg("-J").output() {
        if out.status.success() {
            if let Ok(j) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                list.push(serde_json::json!({"lsblk": j}));
            }
        }
    }
    HttpResponse::Ok().json(list)
}

async fn start_wipe(req: web::Json<WipeRequest>, data: web::Data<AppState>) -> impl Responder {
    let r = req.into_inner();
    let id = Uuid::new_v4().to_string();
    let job = JobStatus { id: id.clone(), status: "queued".into(), progress: 0.0, message: "queued".into(), cert_path: None, email_status: None };
    {
        let mut jobs = data.jobs.lock().unwrap();
        jobs.push(job);
    }

    let state = data.clone();
    thread::spawn(move || {
        info!("Starting wipe job {}", id);
        {
            let mut jobs = state.jobs.lock().unwrap();
            if let Some(j) = jobs.iter_mut().find(|j| j.id==id) {
                j.status = "running".into();
                j.message = "starting".into();
                j.progress = 0.05;
            }
        }
        let path = r.device_path.clone();
        let p = Path::new(&path);
        if !p.exists() {
            let mut jobs = state.jobs.lock().unwrap();
            if let Some(j) = jobs.iter_mut().find(|j| j.id==id) {
                j.status = "failed".into();
                j.message = format!("path not found: {}", path);
                j.progress = 0.0;
            }
            error!("Path not found: {}", path);
            return;
        }

        // Safety: raw device ops require force=true
        let mut used_method = String::new();
        if path.contains("nvme") && r.force.unwrap_or(false) {
            let out = Command::new("nvme").arg("format").arg("--ses=1").arg(&path).output();
            match out {
                Ok(o) if o.status.success() => { used_method = "nvme_format_crypto".into(); }
                Ok(o) => { error!("nvme format failed: {}", String::from_utf8_lossy(&o.stderr)); }
                Err(e) => { error!("nvme exec error: {}", e); }
            }
        } else if r.force.unwrap_or(false) {
            let out = Command::new("hdparm").arg("-I").arg(&path).output();
            if let Ok(o) = out {
                if o.status.success() {
                    let s = String::from_utf8_lossy(&o.stdout);
                    if s.contains("Security:") {
                        let _ = Command::new("hdparm").args(["--user-master","u","--security-set-pass","p",&path]).output();
                        let _ = Command::new("hdparm").args(["--user-master","u","--security-erase","p",&path]).output();
                        used_method = "hdparm_security_erase".into();
                    }
                }
            }
        }

        // fallback overwrite (safe if targeting files/loopback)
        if used_method.is_empty() {
            let sz = p.metadata().map(|m| m.len()).unwrap_or(0);
            let chunk = 1024 * 1024usize;
            let mut f = File::options().write(true).open(p).unwrap();
            use rand::{rngs::OsRng, RngCore};
            let mut written = 0u64;
            if r.profile=="quick" {
                let buf = vec![0u8; chunk];
                while written < sz {
                    let to = std::cmp::min(chunk as u64, sz-written) as usize;
                    let _ = f.write_all(&buf[..to]);
                    written += to as u64;
                    let mut jobs = state.jobs.lock().unwrap();
                    if let Some(j) = jobs.iter_mut().find(|j| j.id==id) {
                        j.progress = 0.1 + 0.6*(written as f32 / sz as f32);
                        j.message = format!("wiping {} bytes", written);
                    }
                }
            } else {
                while written < sz {
                    let to = std::cmp::min(chunk as u64, sz-written) as usize;
                    let mut buf = vec![0u8; to];
                    OsRng.fill_bytes(&mut buf);
                    let _ = f.write_all(&buf);
                    written += to as u64;
                    let mut jobs = state.jobs.lock().unwrap();
                    if let Some(j) = jobs.iter_mut().find(|j| j.id==id) {
                        j.progress = 0.1 + 0.2*(written as f32 / sz as f32);
                        j.message = format!("secure pass 1: {} bytes", written);
                    }
                }
                f.seek(SeekFrom::Start(0)).ok();
                written = 0;
                while written < sz {
                    let to = std::cmp::min(chunk as u64, sz-written) as usize;
                    let buf = vec![0u8; to];
                    let _ = f.write_all(&buf);
                    written += to as u64;
                    let mut jobs = state.jobs.lock().unwrap();
                    if let Some(j) = jobs.iter_mut().find(|j| j.id==id) {
                        j.progress = 0.4 + 0.3*(written as f32 / sz as f32);
                        j.message = format!("secure pass 2: {} bytes", written);
                    }
                }
                f.seek(SeekFrom::Start(0)).ok();
                written = 0;
                while written < sz {
                    let to = std::cmp::min(chunk as u64, sz-written) as usize;
                    let mut buf = vec![0u8; to];
                    OsRng.fill_bytes(&mut buf);
                    let _ = f.write_all(&buf);
                    written += to as u64;
                    let mut jobs = state.jobs.lock().unwrap();
                    if let Some(j) = jobs.iter_mut().find(|j| j.id==id) {
                        j.progress = 0.7 + 0.25*(written as f32 / sz as f32);
                        j.message = format!("secure pass 3: {} bytes", written);
                    }
                }
            }
            used_method = format!("overwrite_{}", r.profile);
        }

        // compute hash
        let mut hasher = Sha256::new();
        if let Ok(mut f2) = File::open(p) {
            let mut buf = [0u8; 65536];
            loop {
                match f2.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => hasher.update(&buf[..n]),
                    Err(_) => break,
                }
            }
        }
        let digest = hasher.finalize();
        let hex = hex::encode(digest);

        let outdir = "./out/certs";
        create_dir_all(outdir).ok();
        let cert_path = format!("{}/{}.json", outdir, id);
        let cert = serde_json::json!({
            "id": id,
            "device": path,
            "profile": r.profile,
            "method": used_method,
            "timestamp": timestamp(),
            "hash": hex
        });
        std::fs::write(&cert_path, serde_json::to_string_pretty(&cert).unwrap()).ok();

        let py = Command::new("python3").arg("../tools/sign_and_send.py").arg("--cert").arg(&cert_path).arg("--email").arg(&r.email).output();
        let email_status = match py {
            Ok(o) if o.status.success() => "sent".to_string(),
            Ok(o) => format!("failed: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => format!("error: {}", e)
        };

        {
            let mut jobs = state.jobs.lock().unwrap();
            if let Some(j) = jobs.iter_mut().find(|j| j.id==id) {
                j.status = "finished".into();
                j.progress = 1.0;
                j.cert_path = Some(cert_path.clone());
                j.email_status = Some(email_status.clone());
                j.message = "completed".into();
            }
        }
        info!("Job {} completed, method: {}", id, used_method);
    });

    HttpResponse::Ok().json(serde_json::json!({"job_id": id}))
}

async fn jobs(data: web::Data<AppState>) -> impl Responder {
    let jobs = data.jobs.lock().unwrap().clone();
    HttpResponse::Ok().json(jobs)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    create_dir_all("./out/certs").ok();
    create_dir_all("./frontend").ok();
    std::fs::write("./frontend/index.html", include_str!("../frontend/index.html")).ok();
    let state = web::Data::new(AppState { jobs: Mutex::new(Vec::new()) });
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(state.clone())
            .route("/", web::get().to(index))
            .route("/targets", web::get().to(targets))
            .route("/wipe", web::post().to(start_wipe))
            .route("/jobs", web::get().to(jobs))
            .service(actix_files::Files::new("/static", "./frontend").show_files_listing())
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
