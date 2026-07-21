// Cover presets default to GUI. Keep this on every filled Windows agent binary.
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    // Retain compile-time filler blobs + import anchors through LTO.
    // Must run on every process start (first line of real agents too).
    binary_filler::keep!();

    #[cfg(not(windows))]
    {
        eprintln!(
            "dummy-agent: binary-filler keep() ok (cover baked at compile time; PE resources require windows target)"
        );
    }

    #[cfg(windows)]
    {
        // Stand-in for agent runtime entry. Real implants replace this body.
        std::process::exit(0);
    }
}
