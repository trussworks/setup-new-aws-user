# setup-new-aws-user

This script creates a virtual MFA device and rotates access keys for a new AWS user.

## Installation

Installation instructions will go here.

## Usage

Usage information will go here. Until then, an example can be found in the
[legendary-waddle](https://github.com/trussworks/legendary-waddle/blob/master/docs/how-to/setup-new-user.md)
repository.

## Dev setup

1. First, install these packages:
   - `brew install pre-commit`
   - `brew install direnv`
1. Next, clone the project repository.
1. Finally, run these commands inside the local repo:
   - `pre-commit install --install-hooks`
   - `direnv allow`
1. The `.envrc` will be loaded if `direnv` is installed.
