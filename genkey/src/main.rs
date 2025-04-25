use iced::{
    Application, Command, Element, Settings, Length, executor,
};
use iced::widget::{Column, Text, TextInput, Button, Container};
use iced::alignment::Alignment;
use async_std::task;
#[derive(Debug, Clone)]
enum Message {
    GenerateKey,
    KeyGenerated(String),
    KeyLengthChanged(String),
    CoresChanged(String),
}
struct MyApp {
    key_length: String,
    cores: String,
    generating: bool,
    message: String,
}
impl Default for MyApp {
    fn default() -> Self {
        Self {
            key_length: "2048".to_owned(),
            cores: "1".to_owned(),
            generating: false,
            message: "".to_owned(),
        }
    }
}
impl Application for MyApp {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = iced::Theme;
    type Flags = ();
    fn new(_flags: ()) -> (Self, Command<Self::Message>) {
        (MyApp::default(), Command::none())
    }
    fn title(&self) -> String {
        "RSA Key Generator".to_string()
    }
    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::KeyLengthChanged(new_val) => {
                self.key_length = new_val;
                Command::none()
            }
            Message::CoresChanged(new_val) => {
                self.cores = new_val;
                Command::none()
            }
            Message::GenerateKey => {
                if self.generating {
                    return Command::none();
                }
                self.generating = true;
                self.message = "Starte RSA-Schlüsselerzeugung...".to_string();
                let key_length = self.key_length.parse::<usize>().unwrap_or(2048);
                let cores = self.cores.parse::<usize>().unwrap_or(1);
                Command::perform(generate_key(key_length, cores), Message::KeyGenerated)
            }
            Message::KeyGenerated(result) => {
                self.generating = false;
                self.message = result;
                Command::none()
            }
        }
    }
    fn view(&self) -> Element<Self::Message> {
        let content = Column::new()
            .padding(20)
            .spacing(10)
            .align_items(Alignment::Center)
            .push(Text::new("RSA Key Generator").size(30))
            .push(Text::new(format!("Verfügbare CPU-Kerne: {}", num_cpus::get())))
            .push(Text::new("Schlüssellänge (Bits):"))
            .push(
                TextInput::new("2048", &self.key_length)
                    .on_input(Message::KeyLengthChanged)
                    .padding(10)
                    .size(20)
            )
            .push(Text::new("Anzahl zu verwendender CPU-Kerne:"))
            .push(
                TextInput::new("1", &self.cores)
                    .on_input(Message::CoresChanged)
                    .padding(10)
                    .size(20)
            )
            .push(
                Button::new(Text::new("Generate Key"))
                    .on_press(Message::GenerateKey)
                    .padding(10)
            )
            .push(Text::new(&self.message).size(20));
        Container::new(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
}
async fn generate_key(key_length: usize, cores: usize) -> String {
    task::spawn_blocking(move || {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use crossbeam::channel;
        use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, pkcs8::EncodePublicKey};
        use rand::rngs::OsRng;
        use std::fs::File;
        use std::io::Write;
        use std::thread;
        let (tx, rx) = channel::bounded(1);
        let found = Arc::new(AtomicBool::new(false));
        for _ in 0..cores {
            let tx = tx.clone();
            let found_clone = found.clone();
            thread::spawn(move || {
                if found_clone.load(Ordering::Relaxed) {
                    return;
                }
                let mut rng = OsRng;
                let key = RsaPrivateKey::new(&mut rng, key_length).unwrap();
                if found_clone.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    tx.send(key).unwrap();
                }
            });
        }
        let key = rx.recv().unwrap();
        let priv_pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        let mut priv_file = File::create("priv.key").unwrap();
        priv_file.write_all(priv_pem.as_bytes()).unwrap();
        let public_key = key.to_public_key();
        let pub_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let mut pub_file = File::create("pub.key").unwrap();
        pub_file.write_all(pub_pem.as_bytes()).unwrap();
        let mut key_file = File::create("key_length.txt").unwrap();
        write!(key_file, "{}", key_length).unwrap();
        "RSA-Schlüsselerzeugung abgeschlossen!".to_owned()
    })
    .await
}
fn main() {
    MyApp::run(Settings::default()).unwrap();
}