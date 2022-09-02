# Examples

The project contains examples of communicating with a real device or speculos (ledger nano  emulator) via javascript (typescript).

## Install deps

```shell
$ yarn
```

## Run

```bash
# to run a sign test on a real device
$ yarn run sign-real

# to run a sign test on speculos
$ yarn run sign-speculos
```

### Notes

No need to compile typescript before running. The project uses `ts-node` which can run typescript files directly.

```bash
$ npx ts-node ./src/sign-real-device
# or
$ ./node_modules/.bin/ts-node ./src/sign-real-device
# or
$ yarn run ts-node ./src/sign-real-device
```
