# psyml

![build](https://github.com/xiaket/psyml/workflows/ci/badge.svg)

## The lifecycle of a yml file.

The user will prepare a yml file that looks like this:

```yaml
path: /apps/superman/
region: us-east-1
kmskey: alias/superman

tags:
  cost_center: team17
  project: superman

parameters:
  - name: api_version
    description: The version of the API endpoint, not a secret.
    type: String
    value: 2

  - name: api_token
    description: The token used to communicate with the API endpoint, typically a secret
    type: SecureString
    value: 5a5468-786448467a59-326436
```

Note here all secrets are in plain text. In order to save this into our codebase, we save the file as `superman.nonprod.yml`, login to our AWS account from the commandline, then run:

`psyml encrypt superman.nonprod.yml`

This will generate a file that looks like this:

```yaml
path: /apps/superman/
region: us-west-1
kmskey: alias/superman
encrypted_with: arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab

tags:
  cost_center: team17
  project: superman
  owner: platform

parameters:
  - name: api_version
    description: The version of the API endpoint, not a secret.
    type: string
    value: 2
  - name: api_token
    description: The token used to communicate with the API endpoint, typically a secret
    type: securestring
    value: AQECAHiuImqexTQGWMAtOjKMcH5UIxXuSZ5WSGx3WKO+VsUI3AAAAKIwgZ8GCsqGSIb3DQEHBqCBkTCBjgIBADCBiAyJKoZIhvcNAQcBMB4GCWCGSAFLAwQBLjARBAwT3cwVGtUYHz02irsCARCAW8a4Tp7pL+inl7Je7x1xEr84Q4lN11t3dNFVycpMZALe185DYow4i1GlaJnJnB7g6V1ZaiB+b+Diap/5AuM/K3bjLmcTq0molBnn2TG3r0uj70lP0FSqP+XwQ+8=
```

Note that we have added an extra field named `encrypted_with`, which is the current id of the KMS key(`alias/psyml`) used to encrypt our secrets. Moreover, the type of the parameter is changed into lowercase characters.

The maintainance of this yml file should not be too difficult. If we need to add configurations, just add it into the yml file and that's it. If we need to add secrets, add the map into parameters, make sure that the value is in plaintext and the type is `SecureString`. After that, run `psyml encrypt filename.yml` again, this time, psyml will ignore all encrypted parameters and just encrypt the new ones using the keyid in `encrypted_with`. To remove entries, please first remove the relevant entry in parameter store before remove the map in the yml file, not because we have any dependencies, but because it is really easy to forget the cleanup process.

## Keys used in the process

We devoted a separate section for the use of KMS in this tool, because it indeed could be a bit confusing.

To be clear, we have used two set of keys, one(`alias/psyml`) is only used for local encryption so that our secrets can be securily saved into our codebase. The other KMS key is specified by the user in `kmskey` field in the yml file, and it is used for actual parameter store encryption. So when we run `psyml encrypt`, we will encrypt the value using `alias/psyml`. When we run `psyml decrypt`, we will still be using `alias/psyml` to decrypt the values. In `psyml save` however, we will first use `alias/psyml` to decrypt the value in memory, then use `kmskey` to do the parameter store upload.

The key, `alias/psyml` is created in each account and we use this key to encrypt all the secrets in the yaml files. This key will not be used for parameter encryption in ssm. We are not going to create one CMK per region because it is not necessary. The default region for this key is Sydney(`ap-southeast-2`) because we are in Australia, and you can change this behaviour by setting environment variable `PSYML_KEY_REGION` to something like `us-east-2`. If you don't like our alias, you can set that to something else too, using the environment variable `PSYML_KEY_ALIAS`.

In this tool, when we first run `encrypt` and we don't have that `alias/psyml` key in place, the tool will try to create it for you. Please note that this may fail due to permission issues, and if that's the case, please provision the key and the alias using a more powerful role.

## A short bio of all available actions.

commandline syntax looks like:

`psyml [action] filename.yml`, where action could be one of:

* `encrypt`: encrypt a yml file with default kms key(`alias/psyml`).
* `save`: save parameters into parameter store using specified KMS key.
* `nuke`: remove all the parameter store entries specified in the yml file.
* `decrypt`: decrypt a yml file and write output to stdout.
* `refresh`: encrypt a yml file using the current `alias/psyml`.
* `export`: export all variables bash-like so it can be sourced.

* `diff`: compare parameters in parameter store with local version.
* `sync`: update parameters in parameter store so it's in sync with yml.

## Known limitations

* Some of the commands(`diff`/`sync`) are not implemented yet.
* parameter store type `StringList` is not supported yet.
* We are using the KMS service and please check [the KMS pricing page](https://aws.amazon.com/kms/pricing/) before continue.
