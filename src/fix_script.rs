use alhalo::PermissionResults;

pub fn generate_fix_script(results: &[PermissionResults]) -> String {
    let mut script = String::from("#!/bin/bash\n# HALO Permission Fix Script\n\n");
    for res in results {
        if res.status == alhalo::Status::Fail {
            script.push_str(&format!(
                "chmod {:o} {}\n",
                res.expected_mode,
                res.path.display()
            ));
        }
    }
    script
}

// Future: Add support for ownership fixes, symlink handling, etc.
