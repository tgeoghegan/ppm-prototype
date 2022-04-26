# ppm-prototype

A prototype implementation of the [Privacy Preserving Measurement][ppm-doc]
protocol.

[ppm-doc]: https://github.com/abetterinternet/ppm-specification

# This project is obsolete

`ppm-prototype` implements an obsolete version of the PPM specification. It will
not receive further updates, nor will bug reports be investigated.

## Config files

The various binary targets get all their configuration (PPM parameters and HPKE
configs) from JSON files found in the standard location for config files. On
Linux, that's `~/.config/ppm-prototype` [elsewhere on other platforms](https://docs.rs/directories/3.0.2/directories/index.html).

To get started on Linux, you can use the config files from `sample-config`:

    cp sample-config/parameters.json ~/.config/ppm-prototype/
    cp sample-config/hpke.json ~/.config/ppm-prototype/

## Leader

Run the leader thusly:

    cargo run --bin leader

The leader will listen for connections on `0.0.0.0` at the port specified in
`parameters.json`. It will advertise the HPKE config in `hpke.json`.

## Helper

Run the helper thusly:

    cargo run --bin helper

The helper will listen for connections on `0.0.0.0` at the port specified in
`parameters.json`. It will advertise the HPKE config in `hpke.json`.

## Client

Once the leader and helper are running, run the client thusly:

    cargo run --bin client

The client will generate random reports, encrypt them to the HPKE config
advertised by the leader specified in `parameters.json` and upload them. The
leader and helper will execute the aggregate protocol together.

## Collector

After the client uploads inputs, run the collector thusly:

    cargo run --bin collector

The helper and leader will execute the collect protocol together and transmit
output shares to the collector, reassembling them into an aggregate.
