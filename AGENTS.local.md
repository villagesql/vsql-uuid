# Local Development Notes for Claude

## Build

```bash
mkdir -p build && cd build
cmake .. -DVillageSQL_BUILD_DIR=~/build
make
make install
```

## Running Tests

To run the UUID extension tests:
```bash
cd ~/build/mysql-test && perl mysql-test-run.pl --suite=/Users/deesix/Source/vsql-uuid/test
```

To record new result files after changing tests:
```bash
cd ~/build/mysql-test && perl mysql-test-run.pl --suite=/Users/deesix/Source/vsql-uuid/test --record
```
