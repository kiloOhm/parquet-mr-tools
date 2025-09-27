java -jar ./encrypted-parquet-generator/build/libs/encrypted-parquet-generator-1.0.0.jar ./demo-encrypted.parquet "0123456789abcdef" --rows=5 --aadPrefix=myTenant --algo=gcm

java -jar ./encrypted-parquet-inspector/build/libs/encrypted-parquet-inspector-1.0.0.jar ./demo-encrypted.parquet "0123456789abcdef"