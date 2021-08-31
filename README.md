# ppm-prototype

A prototype implementation of the [Privacy Preserving Measurement][ppm-doc]
protocol.

[ppm-doc]: https://github.com/abetterinternet/prio-documents

## Config files

The various binary targets get all their configuration (PPM parameters and HPKE
configs) from JSON files found in the standard location for config files. On
Linux, that's `~/.config/ppm-prototype` [elsewhere on other platforms](https://docs.rs/directories/3.0.2/directories/index.html).

To get started, you can use the config files from `sample-config`:

    cp sample-config/parameters.json ~/.config/ppm-prototype/
    cp sample-config/hpke.json ~/.config/ppm-prototype/

## Leader

Run the leader thusly:

    cargo run --bin leader

The leader will listen for connections on `0.0.0.0` at the port specified in
`parameters.json`. It will advertise the HPKE config in `hpke.json`.

## Client

Run the client thusly:

    cargo run --bin client

The client will generate a random report, encrypt it to the HPKE config
advertised by the leader specified in `parameters.json` and upload it.
