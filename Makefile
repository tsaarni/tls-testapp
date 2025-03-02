# Use this Makefile to create certificates for the TLS test app environment.
#
# The certificates are generated by certyaml tool:
#   https://github.com/tsaarni/certyaml/releases/
#
# Usage:
#   make certs
#   make clean   # Remove the generated certificates
#
# The generated certificates are stored in the `certs` directory.

certs: certyaml
	mkdir -p certs
	certyaml -d certs configs/certs.yaml

clean:
	rm -f certs/*.pem certs/certs.state
	rmdir certs
