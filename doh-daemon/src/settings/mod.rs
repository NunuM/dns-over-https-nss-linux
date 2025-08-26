use configparser::ini::Ini;

#[derive(Clone, Debug, PartialEq)]
pub enum Provider {
    Google,
    Cloudflare,
}

#[derive(Clone, Debug)]
pub enum TTlConfig {
    Default,
    Custom(u64),
}


#[derive(Clone, Debug)]
pub struct SQLiteSettings {
    connection_str: String,
}

impl SQLiteSettings {
    pub fn connection_str(&self) -> &str {
        &self.connection_str
    }
}

#[derive(Debug)]
#[derive(Clone)]
pub struct ApplicationSettings {
    provider: Provider,
    ttl: TTlConfig,
    sqlite: SQLiteSettings,
}


impl ApplicationSettings {
    pub fn provider(&self) -> &Provider {
        &self.provider
    }

    pub fn ttl(&self) -> &TTlConfig {
        &self.ttl
    }
    pub fn sqlite(&self) -> &SQLiteSettings {
        &self.sqlite
    }

    pub fn configs() -> Self {
        let config_file = std::env::var("CONFIG_FILE").unwrap_or("/etc/frost-doh/config.prod.ini".to_string());
        //let config_file = std::env::var("CONFIG_FILE").unwrap_or("doh-daemon/config.ini".to_string());

        let mut config = Ini::new();

        let _ = config.load(config_file)
            .expect("configuration file must be present");

        let provider = match config.get("resolver", "provider") {
            Some(s) => {
                if s.eq("cloudflare") {
                    Provider::Cloudflare
                } else {
                    Provider::Google
                }
            }
            None => Provider::Google
        };

        let ttl = match config.get("resolver", "ttl") {
            Some(str) => {
                if str.eq("default") {
                    TTlConfig::Default
                } else {
                    let time = str
                        .parse::<u64>()
                        .unwrap_or(60);

                    TTlConfig::Custom(time)
                }
            }
            None => TTlConfig::Default
        };

        let dn_connection = config.get("sqlite", "connection").unwrap_or("doh.db".to_string());


        Self {
            provider,
            ttl,
            sqlite: SQLiteSettings {
                connection_str: dn_connection
            },
        }
    }
}