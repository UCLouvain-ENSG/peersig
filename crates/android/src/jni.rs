//! The bridge to the Kotlin side: `be.uclouvain.peersig.Native`'s native
//! methods, and the calls back to its `Host` (android/app/src/main/java).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{Global, JClass, JObject, JString};
use jni::sys::jint;
use jni::{jni_sig, jni_str, Env, EnvUnowned, JValue, JavaVM};

use crate::apps::PackageFacts;
use crate::{Android, Java};

static ANDROID: OnceLock<Android> = OnceLock::new();

/// The Kotlin `Host`, called from any thread.
struct KotlinHost {
    vm: JavaVM,
    host: Global<JObject<'static>>,
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

impl KotlinHost {
    fn string_of(env: &mut Env, obj: JObject) -> jni::errors::Result<Option<String>> {
        if obj.is_null() {
            return Ok(None);
        }
        let s = env.cast_local::<JString>(obj)?;
        Ok(Some(s.try_to_string(env)?))
    }

    /// Calls a `void` method of the host with string arguments.
    fn say(&self, method: &'static str, texts: &[&str]) {
        let r = self.vm.attach_current_thread(|env| -> jni::errors::Result<()> {
            let mut strings = Vec::new();
            for t in texts {
                strings.push(JString::from_str(env, t)?);
            }
            let args: Vec<JValue> = strings.iter().map(|s| JValue::Object(s)).collect();
            let name = jni::strings::JNIString::new(method);
            match texts.len() {
                1 => env.call_method(self.host.as_obj(), &name, jni_sig!("(Ljava/lang/String;)V"), &args)?,
                _ => env.call_method(self.host.as_obj(), &name, jni_sig!("(Ljava/lang/String;Ljava/lang/String;)V"), &args)?,
            };
            Ok(())
        });
        if let Err(e) = r {
            log::warn!("{}: {}", method, e);
        }
    }
}

impl Java for KotlinHost {
    fn owner_uid(&self, proto: u8, src: SocketAddr, dst: SocketAddr) -> Option<u32> {
        let r = self.vm.attach_current_thread(|env| -> jni::errors::Result<jint> {
            let s = env.byte_array_from_slice(&octets(src.ip()))?;
            let d = env.byte_array_from_slice(&octets(dst.ip()))?;
            env.call_method(
                self.host.as_obj(),
                jni_str!("ownerUid"),
                jni_sig!("(I[BI[BI)I"),
                &[JValue::Int(proto as jint), JValue::Object(&s), JValue::Int(src.port() as jint), JValue::Object(&d), JValue::Int(dst.port() as jint)],
            )?
            .i()
        });
        match r {
            Ok(uid) if uid >= 0 => Some(uid as u32),
            Ok(_) => None,
            Err(e) => {
                log::warn!("ownerUid: {}", e);
                None
            }
        }
    }

    fn package_facts(&self, uid: u32) -> Option<PackageFacts> {
        let r = self.vm.attach_current_thread(|env| -> jni::errors::Result<Option<String>> {
            let v = env.call_method(self.host.as_obj(), jni_str!("packageFacts"), jni_sig!("(I)Ljava/lang/String;"), &[JValue::Int(uid as jint)])?.l()?;
            Self::string_of(env, v)
        });
        match r {
            Ok(Some(s)) if !s.is_empty() => serde_json::from_str(&s).map_err(|e| log::warn!("packageFacts: {}", e)).ok(),
            Ok(_) => None,
            Err(e) => {
                log::warn!("packageFacts: {}", e);
                None
            }
        }
    }

    fn capture_allowed(&self) -> bool {
        self.vm
            .attach_current_thread(|env| -> jni::errors::Result<bool> {
                env.call_method(self.host.as_obj(), jni_str!("captureAllowed"), jni_sig!("()Z"), &[])?.z()
            })
            .unwrap_or(false)
    }

    fn notify(&self, body: &str) {
        self.say("notify", &[body]);
    }

    fn state(&self, view: &str, tray: &str) {
        self.say("state", &[view, tray]);
    }
}

fn android() -> jni::errors::Result<&'static Android> {
    ANDROID.get().ok_or(jni::errors::Error::NullPtr("PeerSig is not initialized"))
}

fn string(env: &Env, s: &JString) -> jni::errors::Result<String> {
    if s.is_null() {
        return Ok(String::new());
    }
    s.try_to_string(env)
}

/// `Native.init(context, host, filesDir)`: once per process, from the
/// Application. Loads the state and starts the reports' worker.
#[no_mangle]
pub extern "system" fn Java_be_uclouvain_peersig_Native_init<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    context: JObject<'l>,
    host: JObject<'l>,
    files: JString<'l>,
) {
    unowned
        .with_env(|env| -> Result<(), jni::errors::Error> {
            if ANDROID.get().is_some() {
                return Ok(());
            }
            android_logger::init_once(android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("peersig"));
            // reqwest checks the server's certificate with Android's own
            // trust store.
            rustls_platform_verifier::android::init_with_env(env, context)?;
            let files = PathBuf::from(string(env, &files)?);
            let vm = env.get_java_vm()?;
            let host = env.new_global_ref(&host)?;
            let java: Arc<dyn Java> = Arc::new(KotlinHost { vm, host });
            match Android::new(&files, java) {
                Ok(a) => {
                    let _ = ANDROID.set(a);
                }
                Err(e) => log::error!("init: {:#}", e),
            }
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Native.command(name, argsJson)`: the window's commands; answers
/// `{"ok": ...}` or `{"err": "..."}`. Blocks: called off the main thread.
#[no_mangle]
pub extern "system" fn Java_be_uclouvain_peersig_Native_command<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    cmd: JString<'l>,
    args: JString<'l>,
) -> JString<'l> {
    unowned
        .with_env(|env| -> Result<JString<'l>, jni::errors::Error> {
            let (cmd, args) = (string(env, &cmd)?, string(env, &args)?);
            let out = android()?.command_json(&cmd, &args);
            JString::from_str(env, out)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Native.startCapture(fd)`: takes the VPN interface. Answers "" or why
/// it could not start.
#[no_mangle]
pub extern "system" fn Java_be_uclouvain_peersig_Native_startCapture<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    fd: jint,
) -> JString<'l> {
    unowned
        .with_env(|env| -> Result<JString<'l>, jni::errors::Error> {
            let why = android()?.start_capture(fd).err().unwrap_or_default();
            JString::from_str(env, why)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Native.stopCapture(why)`: closes the VPN interface. `why` (or null) is
/// shown in the window.
#[no_mangle]
pub extern "system" fn Java_be_uclouvain_peersig_Native_stopCapture<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    why: JString<'l>,
) {
    unowned
        .with_env(|env| -> Result<(), jni::errors::Error> {
            let why = string(env, &why)?;
            android()?.stop_capture((!why.is_empty()).then_some(why));
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Native.setDns("192.168.1.1,2001:db8::1")`: the network's DNS servers.
#[no_mangle]
pub extern "system" fn Java_be_uclouvain_peersig_Native_setDns<'l>(
    mut unowned: EnvUnowned<'l>,
    _class: JClass<'l>,
    servers: JString<'l>,
) {
    unowned
        .with_env(|env| -> Result<(), jni::errors::Error> {
            let s = string(env, &servers)?;
            let ips = s.split(',').filter_map(|x| x.trim().parse::<IpAddr>().ok()).collect();
            android()?.set_dns(ips);
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}
