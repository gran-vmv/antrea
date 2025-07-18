# flow-aggregator

![Version: 2.4.0-dev](https://img.shields.io/badge/Version-2.4.0--dev-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: latest](https://img.shields.io/badge/AppVersion-latest-informational?style=flat-square)

Antrea Flow Aggregator

**Homepage:** <https://antrea.io/>

## Source Code

* <https://github.com/antrea-io/antrea>

## Requirements

Kubernetes: `>= 1.19.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| activeFlowRecordTimeout | string | `"60s"` | Provide the active flow record timeout as a duration string. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h". |
| aggregatorTransportProtocol | string | `"tls"` | Provide the transport protocol for the flow aggregator collecting process, which must be one of "tls", "tcp", "udp" or "none". Note that this only applies to the IPFIX collector. The gRPC collector will always run (and always use mTLS), regardless of this configuration. When using "none", the IPFIX collector will be disabled. |
| antreaNamespace | string | `"kube-system"` | Namespace in which Antrea was installed. |
| apiServer.apiPort | int | `10348` | The port for the Flow Aggregator APIServer to serve on. |
| apiServer.tlsCipherSuites | string | `""` | Comma-separated list of cipher suites that will be used by the Flow Aggregator APIservers. If empty, the default Go Cipher Suites will be used. |
| apiServer.tlsMinVersion | string | `""` | TLS min version from: VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13. |
| autoscaling.cpu.averageUtilization | int | `70` | AverageUtilization is the target average CPU utilization. |
| autoscaling.enable | bool | `false` | Enable installs the HPA for flow-aggregator. This must be disabled when running in "Aggregate" mode. |
| autoscaling.maxReplicas | int | `10` | MaxReplicas is the maximum number of replicas for autoscaling. This value must be greater than or equal to autoscaling.minReplicas |
| autoscaling.minReplicas | int | `1` | MinReplicas is the minimum number of replicas for autoscaling. This value must be less than or equal to autoscaling.maxReplicas |
| clickHouse.commitInterval | string | `"8s"` | CommitInterval is the periodical interval between batch commit of flow records to DB. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h". |
| clickHouse.compress | bool | `true` | Compress enables lz4 compression when committing flow records. |
| clickHouse.connectionSecret | object | `{"password":"clickhouse_operator_password","username":"clickhouse_operator"}` | Credentials to connect to ClickHouse. They will be stored in a Secret. |
| clickHouse.databaseURL | string | `"tcp://clickhouse-clickhouse.flow-visibility.svc:9000"` | DatabaseURL is the url to the database. Provide the database URL as a string with format <Protocol>://<ClickHouse server FQDN or IP>:<ClickHouse port>. The protocol has to be one of the following: "tcp", "tls", "http", "https". When "tls" or "https" is used, tls will be enabled. |
| clickHouse.debug | bool | `false` | Debug enables debug logs from ClickHouse sql driver. |
| clickHouse.enable | bool | `false` | Determine whether to enable exporting flow records to ClickHouse. |
| clickHouse.tls.caCert | bool | `false` | Indicates whether to use custom CA certificate. Default root CAs will be used if this field is false. If true, a Secret named "clickhouse-ca" must be provided with the following keys: ca.crt: <CA certificate> |
| clickHouse.tls.insecureSkipVerify | bool | `false` | Determine whether to skip the verification of the server's certificate chain and host name. Default is false. |
| clusterID | string | `""` | Provide a clusterID to be added to records. This is only consumed by the flowCollector (IPFIX) exporter. |
| dnsPolicy | string | `""` | DNS Policy for the flow-aggregator Pod. If empty, the Kubernetes default will be used. |
| flowAggregator.resources | object | `{"requests":{"cpu":"500m","memory":"256Mi"}}` | Resource requests and limits for the flow-aggregator container. |
| flowAggregator.securityContext | object | `{}` | Configure the security context for the flow-aggregator container. |
| flowAggregatorAddress | string | `""` | Provide an extra DNS name or IP address of flow aggregator for generating TLS certificate. |
| flowCollector.address | string | `""` | Provide the flow collector address as string with format <IP>:<port>[:<proto>],  where proto is tcp or udp. If no L4 transport proto is given, we consider tcp as default. |
| flowCollector.enable | bool | `false` | Determine whether to enable exporting flow records to external flow collector. |
| flowCollector.includeK8sNames | bool | `true` | Include the names of K8s objects (Pods, Nodes, ...) as information elements in exported records. |
| flowCollector.includeK8sUIDs | bool | `false` | Include the UIDs of K8s objects (Pods, Nodes, ...) as information elements in exported records. |
| flowCollector.maxIPFIXMsgSize | int | `0` | Maximum message size to use for IPFIX records. If set to 0 (recommended), a reasonable default value will be used based on the protocol (tcp or udp) used to connect to the collector. Min valid value is 512 and max valid value is 65535. |
| flowCollector.observationDomainID | string | `""` | Provide the 32-bit Observation Domain ID which will uniquely identify this instance of the flow aggregator to an external flow collector. If omitted, an Observation Domain ID will be generated from the persistent cluster UUID generated by Antrea. |
| flowCollector.recordFormat | string | `"IPFIX"` | Provide format for records sent to the configured flow collector. Supported formats are IPFIX and JSON. |
| flowCollector.templateRefreshTimeout | string | `"600s"` | Template retransmission interval when using the udp protocol to export records. The value must be provided as a duration string. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h". |
| flowCollector.tls.caSecretName | string | `""` | Name of the Secret containing the CA certificate used to authenticate the flowCollector. Default root CAs will be used if this field is empty. The Secret must be created in the Namespace in which the Flow Aggregator is deployed, and it must contain the ca.crt key. |
| flowCollector.tls.clientSecretName | string | `""` | Name of the Secret containing the client's certificate and private key for mTLS. If omitted, client authentication will be disabled. The Secret must be created in Namespace in which the Flow Aggregator is deployed, and it must be of type kubernetes.io/tls and contain the tls.crt and tls.key keys. |
| flowCollector.tls.enable | bool | `false` | Enable TLS. |
| flowCollector.tls.minVersion | string | VersionTLS12 | Minimum TLS version from: VersionTLS12, VersionTLS13. |
| flowCollector.tls.serverName | string | `""` | ServerName is used to verify the hostname on the returned certificates. It is also included in the client's handshake (SNI) to support virtual hosting unless it is an IP address. If this field is omitted, the hostname used for certificate verification will default to the provided server address (flowCollector.address). |
| flowLogger.compress | bool | `true` | Compress enables gzip compression on rotated files. |
| flowLogger.enable | bool | `false` | Determine whether to enable exporting flow records to a local log file. |
| flowLogger.filters | list | `[]` | Filters can be used to select which flow records to log to file. The provided filters are OR-ed to determine whether a specific flow should be logged. By default, all flows are logged. With the following filters, only flows which are denied because of a network policy will be logged: [{ingressNetworkPolicyRuleActions: ["Drop", "Reject"]}, {egressNetworkPolicyRuleActions: ["Drop", "Reject"]}] |
| flowLogger.maxAge | int | `0` | MaxAge is the maximum number of days to retain old log files based on the timestamp encoded in their filename. The default (0) is not to remove old log files based on age. |
| flowLogger.maxBackups | int | `3` | MaxBackups is the maximum number of old log files to retain. If set to 0, all log files will be retained (unless MaxAge causes them to be deleted). |
| flowLogger.maxSize | int | `100` | MaxSize is the maximum size in MB of a log file before it gets rotated. |
| flowLogger.path | string | `"/tmp/antrea-flows.log"` | Path is the path to the local log file. |
| flowLogger.prettyPrint | bool | `true` | PrettyPrint enables conversion of some numeric fields to a more meaningful string representation. |
| flowLogger.recordFormat | string | `"CSV"` | RecordFormat defines the format of the flow records logged to file. Only "CSV" is supported at the moment. |
| hostAliases | list | `[]` | HostAliases to be injected into the Pod's hosts file. For example: `[{"ip": "8.8.8.8", "hostnames": ["clickhouse.example.com"]}]` |
| hostNetwork | bool | `false` | Run the flow-aggregator Pod in the host network. With hostNetwork enabled, it is usually necessary to set dnsPolicy to ClusterFirstWithHostNet. |
| image | object | `{"pullPolicy":"IfNotPresent","repository":"antrea/flow-aggregator","tag":""}` | Container image used by Flow Aggregator. |
| inactiveFlowRecordTimeout | string | `"90s"` | Provide the inactive flow record timeout as a duration string. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h". |
| logVerbosity | int | `0` | Log verbosity switch for Flow Aggregator. |
| mode | string | `"Aggregate"` | Mode in which to run the flow aggregator. Must be one of "Aggregate" or "Proxy". In Aggregate mode, flow records received from source and destination are aggregated and sent as one flow record. In Proxy mode, flow records are enhanced with some additional information, then sent directly without buffering or aggregation. |
| priorityClassName | string | `"system-cluster-critical"` | Prority class to use for the flow-aggregator Pod. |
| recordContents.podLabels | bool | `false` | Determine whether source and destination Pod labels will be included in the flow records. |
| replicas | int | `1` | Replicas is the number of flow-aggregator replicas. This must be 1 for "Aggregate" mode. |
| s3Uploader.awsCredentials | object | `{"aws_access_key_id":"changeme","aws_secret_access_key":"changeme","aws_session_token":""}` | Credentials to authenticate to AWS. They will be stored in a Secret and injected into the Pod as environment variables. |
| s3Uploader.bucketName | string | `""` | BucketName is the name of the S3 bucket to which flow records will be uploaded. It is required. |
| s3Uploader.bucketPrefix | string | `""` | BucketPrefix is the prefix ("folder") under which flow records will be uploaded. |
| s3Uploader.compress | bool | `true` | Compress enables gzip compression when uploading files to S3. |
| s3Uploader.enable | bool | `false` | Determine whether to enable exporting flow records to AWS S3. |
| s3Uploader.maxRecordsPerFile | int | `1000000` | MaxRecordsPerFile is the maximum number of records per file uploaded. It is not recommended to change this value. |
| s3Uploader.recordFormat | string | `"CSV"` | RecordFormat defines the format of the flow records uploaded to S3. Only "CSV" is supported at the moment. |
| s3Uploader.region | string | `"us-west-2"` | Region is used as a "hint" to get the region in which the provided bucket is located. An error will occur if the bucket does not exist in the AWS partition the region hint belongs to. |
| s3Uploader.uploadInterval | string | `"60s"` | UploadInterval is the duration between each file upload to S3. |
| testing.coverage | bool | `false` | Enable code coverage measurement (used when testing Flow Aggregator only). |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
