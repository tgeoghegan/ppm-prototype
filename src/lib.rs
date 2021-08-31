pub mod hpke;
pub mod parameters;
pub mod trace;
pub mod upload;

use directories::ProjectDirs;
use std::path::PathBuf;

pub(crate) fn config_path() -> PathBuf {
    let project_path = ProjectDirs::from("org", "isrg", "ppm-prototype").unwrap();
    project_path.config_dir().to_path_buf()
}
