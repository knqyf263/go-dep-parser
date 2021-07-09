package maven

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (

	/* pom.xml
	<project xmlns="http://maven.apache.org/POM/4.0.0"
	  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
	                      http://maven.apache.org/xsd/maven-4.0.0.xsd">

	  <modelVersion>4.0.0</modelVersion>
	  <groupId>io.aquasecurity</groupId>
	  <artifactId>trivy</artifactId>
	  <version>1.0</version>
	  <packaging>jar</packaging>

	  <dependencies>
	    <dependency>
	      <groupId>org.springframework</groupId>
	      <artifactId>spring-core</artifactId>
	      <version>[5.0.1.RELEASE]</version>
	    </dependency>
	  </dependencies>
	</project>
	*/
	// mvn dependency:list -DoutputFile=dependency.txt
	/*
		cat dependency.txt | grep -v "^\s*$" | grep -v "The following files have been resolved" | \
			awk '
			  {
			    cnt=split($1, path, ":")
			    if(cnt == 5){
			      print "{\"" path[1] ":" path[2] "\", \"" path[4] "\"},"
			    }
			    if(cnt == 6){
			      print "{\"" path[1] ":" path[2] "\", \"" path[5] "\"},"
			    }
			  }
			'
	*/
	MavenNormal = []types.Library{
		{"org.springframework:spring-jcl", "5.0.1.RELEASE"},
		{"org.springframework:spring-core", "5.0.1.RELEASE"},
	}

	// git clone https://github.com/apache/hadoop.git
	// git checkout fdd20a3cf4cd9073f443b2bf07eef14f454d4c33
	// cd hadoop/hadoop-hdfs-project/hadoop-hdfs-nfs/
	// mvn dependency:list -DoutputFile=dependency.txt
	/*
		cat dependency.txt | grep -v "^\s*$" | grep -v "The following files have been resolved" | \
			awk '
			  {
			    cnt=split($1, path, ":")
			    if(cnt == 5){
			      print "{\"" path[1] ":" path[2] "\", \"" path[4] "\"},"
			    }
			    if(cnt == 6){
			      print "{\"" path[1] ":" path[2] "\", \"" path[5] "\"},"
			    }
			  }
			'
	*/
	MavenHadoopHDFS = []types.Library{
		{"org.apache.hadoop:hadoop-annotations", "3.4.0-SNAPSHOT"},
		{"org.apache.hadoop:hadoop-auth", "3.4.0-SNAPSHOT"},
		{"org.slf4j:slf4j-api", "1.7.30"},
		{"org.apache.httpcomponents:httpclient", "4.5.13"},
		{"org.apache.httpcomponents:httpcore", "4.4.13"},
		{"com.nimbusds:nimbus-jose-jwt", "9.8.1"},
		{"com.github.stephenc.jcip:jcip-annotations", "1.0-1"},
		{"net.minidev:json-smart", "2.4.2"},
		{"net.minidev:accessors-smart", "2.4.2"},
		{"org.ow2.asm:asm", "5.0.4"},
		{"org.apache.zookeeper:zookeeper", "3.5.6"},
		{"org.apache.curator:curator-framework", "4.2.0"},
		{"org.apache.kerby:kerb-simplekdc", "1.0.1"},
		{"org.apache.kerby:kerb-client", "1.0.1"},
		{"org.apache.kerby:kerby-config", "1.0.1"},
		{"org.apache.kerby:kerb-common", "1.0.1"},
		{"org.apache.kerby:kerb-crypto", "1.0.1"},
		{"org.apache.kerby:kerb-util", "1.0.1"},
		{"org.apache.kerby:token-provider", "1.0.1"},
		{"org.apache.kerby:kerb-admin", "1.0.1"},
		{"org.apache.kerby:kerb-server", "1.0.1"},
		{"org.apache.kerby:kerb-identity", "1.0.1"},
		{"org.apache.kerby:kerby-xdr", "1.0.1"},
		{"org.apache.hadoop:hadoop-nfs", "3.4.0-SNAPSHOT"},
		{"io.netty:netty-all", "4.1.61.Final"},
		{"org.apache.hadoop:hadoop-hdfs", "3.4.0-SNAPSHOT"},
		{"org.eclipse.jetty:jetty-util-ajax", "9.4.40.v20210413"},
		{"io.netty:netty", "3.10.6.Final"},
		{"org.fusesource.leveldbjni:leveldbjni-all", "1.8"},
		{"com.fasterxml.jackson.core:jackson-databind", "2.10.5.1"},
		{"com.fasterxml.jackson.core:jackson-core", "2.10.5"},
		{"org.apache.hadoop:hadoop-hdfs-client", "3.4.0-SNAPSHOT"},
		{"com.squareup.okhttp:okhttp", "2.7.5"},
		{"com.squareup.okio:okio", "1.6.0"},
		{"com.fasterxml.jackson.core:jackson-annotations", "2.10.5"},
		{"org.apache.hadoop:hadoop-hdfs", "3.4.0-SNAPSHOT"},
		{"org.apache.hadoop:hadoop-common", "3.4.0-SNAPSHOT"},
		{"org.apache.hadoop.thirdparty:hadoop-shaded-protobuf_3_7", "1.1.0-SNAPSHOT"},
		{"com.google.guava:guava", "27.0-jre"},
		{"com.google.guava:failureaccess", "1.0"},
		{"com.google.guava:listenablefuture", "9999.0-empty-to-avoid-conflict-with-guava"},
		{"org.checkerframework:checker-qual", "2.5.2"},
		{"com.google.j2objc:j2objc-annotations", "1.1"},
		{"org.codehaus.mojo:animal-sniffer-annotations", "1.17"},
		{"org.apache.commons:commons-math3", "3.1.1"},
		{"commons-net:commons-net", "3.6"},
		{"commons-collections:commons-collections", "3.2.2"},
		{"jakarta.activation:jakarta.activation-api", "1.2.1"},
		{"org.eclipse.jetty:jetty-servlet", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-security", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-webapp", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-xml", "9.4.40.v20210413"},
		{"javax.servlet.jsp:jsp-api", "2.1"},
		{"com.sun.jersey:jersey-servlet", "1.19"},
		{"com.sun.jersey:jersey-json", "1.19"},
		{"org.codehaus.jettison:jettison", "1.1"},
		{"com.sun.xml.bind:jaxb-impl", "2.2.3-1"},
		{"javax.xml.bind:jaxb-api", "2.2.11"},
		{"org.codehaus.jackson:jackson-core-asl", "1.9.13"},
		{"org.codehaus.jackson:jackson-mapper-asl", "1.9.13"},
		{"org.codehaus.jackson:jackson-jaxrs", "1.9.13"},
		{"org.codehaus.jackson:jackson-xc", "1.9.13"},
		{"commons-beanutils:commons-beanutils", "1.9.4"},
		{"org.apache.commons:commons-configuration2", "2.1.1"},
		{"org.apache.commons:commons-lang3", "3.7"},
		{"org.apache.commons:commons-text", "1.4"},
		{"org.apache.avro:avro", "1.7.7"},
		{"com.thoughtworks.paranamer:paranamer", "2.3"},
		{"com.google.re2j:re2j", "1.1"},
		{"com.google.code.gson:gson", "2.2.4"},
		{"com.jcraft:jsch", "0.1.55"},
		{"org.apache.curator:curator-client", "4.2.0"},
		{"org.apache.curator:curator-recipes", "4.2.0"},
		{"com.google.code.findbugs:jsr305", "3.0.2"},
		{"org.apache.commons:commons-compress", "1.19"},
		{"org.apache.kerby:kerb-core", "1.0.1"},
		{"org.apache.kerby:kerby-pkix", "1.0.1"},
		{"org.apache.kerby:kerby-asn1", "1.0.1"},
		{"org.apache.kerby:kerby-util", "1.0.1"},
		{"org.codehaus.woodstox:stax2-api", "4.2.1"},
		{"com.fasterxml.woodstox:woodstox-core", "5.3.0"},
		{"dnsjava:dnsjava", "2.1.7"},
		{"org.xerial.snappy:snappy-java", "1.1.8.2"},
		{"org.apache.hadoop:hadoop-common", "3.4.0-SNAPSHOT"},
		{"org.apache.zookeeper:zookeeper", "3.5.6"},
		{"org.apache.zookeeper:zookeeper-jute", "3.5.6"},
		{"org.apache.yetus:audience-annotations", "0.5.0"},
		{"org.apache.hadoop.thirdparty:hadoop-shaded-guava", "1.1.0-SNAPSHOT"},
		{"org.eclipse.jetty:jetty-server", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-http", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-io", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-util", "9.4.40.v20210413"},
		{"com.sun.jersey:jersey-core", "1.19"},
		{"javax.ws.rs:jsr311-api", "1.1.1"},
		{"com.sun.jersey:jersey-server", "1.19"},
		{"commons-cli:commons-cli", "1.2"},
		{"commons-codec:commons-codec", "1.15"},
		{"commons-io:commons-io", "2.8.0"},
		{"commons-logging:commons-logging", "1.1.3"},
		{"commons-daemon:commons-daemon", "1.0.13"},
		{"log4j:log4j", "1.2.17"},
		{"com.google.protobuf:protobuf-java", "2.5.0"},
		{"javax.servlet:javax.servlet-api", "3.1.0"},
		{"junit:junit", "4.13.1"},
		{"org.hamcrest:hamcrest-core", "1.3"},
		{"org.mockito:mockito-core", "2.28.2"},
		{"net.bytebuddy:byte-buddy", "1.9.10"},
		{"net.bytebuddy:byte-buddy-agent", "1.9.10"},
		{"org.objenesis:objenesis", "2.6"},
		{"org.slf4j:slf4j-log4j12", "1.7.30"},
		{"org.bouncycastle:bcprov-jdk15on", "1.68"},
	}

	// git clone https://github.com/apache/hadoop.git
	// git checkout fdd20a3cf4cd9073f443b2bf07eef14f454d4c33
	// cd hadoop/hadoop-cloud-storage-project
	// mvn dependency:list -DoutputFile=dependency.txt
	/*
		cat dependency.txt | grep -v "^\s*$" | grep -v "The following files have been resolved" | \
			awk '
			  {
			    cnt=split($1, path, ":")
			    if(cnt == 5){
			      print "{\"" path[1] ":" path[2] "\", \"" path[4] "\"},"
			    }
			    if(cnt == 6){
			      print "{\"" path[1] ":" path[2] "\", \"" path[5] "\"},"
			    }
			  }
			'
	*/
	MavenHadoopCloudStorage = []types.Library{
		{"org.apache.hadoop:hadoop-annotations", "3.4.0-SNAPSHOT"},
		{"org.apache.hadoop:hadoop-common", "3.4.0-SNAPSHOT"},
		{"org.apache.hadoop.thirdparty:hadoop-shaded-protobuf_3_7", "1.1.0-SNAPSHOT"},
		{"org.apache.hadoop.thirdparty:hadoop-shaded-guava", "1.1.0-SNAPSHOT"},
		{"com.google.guava:guava", "27.0-jre"},
		{"com.google.guava:failureaccess", "1.0"},
		{"com.google.guava:listenablefuture", "9999.0-empty-to-avoid-conflict-with-guava"},
		{"org.checkerframework:checker-qual", "2.5.2"},
		{"com.google.j2objc:j2objc-annotations", "1.1"},
		{"org.codehaus.mojo:animal-sniffer-annotations", "1.17"},
		{"commons-cli:commons-cli", "1.2"},
		{"org.apache.commons:commons-math3", "3.1.1"},
		{"org.apache.httpcomponents:httpclient", "4.5.13"},
		{"commons-codec:commons-codec", "1.15"},
		{"commons-io:commons-io", "2.8.0"},
		{"commons-net:commons-net", "3.6"},
		{"commons-collections:commons-collections", "3.2.2"},
		{"javax.servlet:javax.servlet-api", "3.1.0"},
		{"jakarta.activation:jakarta.activation-api", "1.2.1"},
		{"org.eclipse.jetty:jetty-server", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-http", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-io", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-util", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-servlet", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-security", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-webapp", "9.4.40.v20210413"},
		{"org.eclipse.jetty:jetty-xml", "9.4.40.v20210413"},
		{"javax.servlet.jsp:jsp-api", "2.1"},
		{"com.sun.jersey:jersey-servlet", "1.19"},
		{"commons-logging:commons-logging", "1.1.3"},
		{"log4j:log4j", "1.2.17"},
		{"commons-beanutils:commons-beanutils", "1.9.4"},
		{"org.apache.commons:commons-configuration2", "2.1.1"},
		{"org.apache.commons:commons-lang3", "3.7"},
		{"org.apache.commons:commons-text", "1.4"},
		{"org.slf4j:slf4j-api", "1.7.30"},
		{"org.slf4j:slf4j-log4j12", "1.7.30"},
		{"org.apache.avro:avro", "1.7.7"},
		{"com.thoughtworks.paranamer:paranamer", "2.3"},
		{"com.google.re2j:re2j", "1.1"},
		{"com.google.protobuf:protobuf-java", "2.5.0"},
		{"com.google.code.gson:gson", "2.2.4"},
		{"org.apache.hadoop:hadoop-auth", "3.4.0-SNAPSHOT"},
		{"com.nimbusds:nimbus-jose-jwt", "9.8.1"},
		{"com.github.stephenc.jcip:jcip-annotations", "1.0-1"},
		{"net.minidev:json-smart", "2.4.2"},
		{"net.minidev:accessors-smart", "2.4.2"},
		{"org.ow2.asm:asm", "5.0.4"},
		{"org.apache.curator:curator-framework", "4.2.0"},
		{"org.apache.kerby:kerb-simplekdc", "1.0.1"},
		{"org.apache.kerby:kerb-client", "1.0.1"},
		{"org.apache.kerby:kerby-config", "1.0.1"},
		{"org.apache.kerby:kerb-common", "1.0.1"},
		{"org.apache.kerby:kerb-crypto", "1.0.1"},
		{"org.apache.kerby:kerb-util", "1.0.1"},
		{"org.apache.kerby:token-provider", "1.0.1"},
		{"org.apache.kerby:kerb-admin", "1.0.1"},
		{"org.apache.kerby:kerb-server", "1.0.1"},
		{"org.apache.kerby:kerb-identity", "1.0.1"},
		{"org.apache.kerby:kerby-xdr", "1.0.1"},
		{"org.apache.curator:curator-client", "4.2.0"},
		{"org.apache.curator:curator-recipes", "4.2.0"},
		{"com.google.code.findbugs:jsr305", "3.0.2"},
		{"org.apache.commons:commons-compress", "1.19"},
		{"org.bouncycastle:bcprov-jdk15on", "1.68"},
		{"org.apache.kerby:kerb-core", "1.0.1"},
		{"org.apache.kerby:kerby-pkix", "1.0.1"},
		{"org.apache.kerby:kerby-asn1", "1.0.1"},
		{"org.apache.kerby:kerby-util", "1.0.1"},
		{"com.fasterxml.jackson.core:jackson-databind", "2.10.5.1"},
		{"com.fasterxml.jackson.core:jackson-core", "2.10.5"},
		{"org.codehaus.woodstox:stax2-api", "4.2.1"},
		{"com.fasterxml.woodstox:woodstox-core", "5.3.0"},
		{"dnsjava:dnsjava", "2.1.7"},
		{"org.xerial.snappy:snappy-java", "1.1.8.2"},
		{"org.apache.hadoop:hadoop-aliyun", "3.4.0-SNAPSHOT"},
		{"com.aliyun.oss:aliyun-sdk-oss", "3.4.1"},
		{"org.jdom:jdom", "1.1"},
		{"org.codehaus.jettison:jettison", "1.1"},
		{"com.aliyun:aliyun-java-sdk-core", "3.4.0"},
		{"com.aliyun:aliyun-java-sdk-ram", "3.0.0"},
		{"com.aliyun:aliyun-java-sdk-sts", "3.0.0"},
		{"com.aliyun:aliyun-java-sdk-ecs", "4.2.0"},
		{"org.apache.hadoop:hadoop-aws", "3.4.0-SNAPSHOT"},
		{"com.amazonaws:aws-java-sdk-bundle", "1.11.901"},
		{"org.wildfly.openssl:wildfly-openssl", "1.0.7.Final"},
		{"org.apache.hadoop:hadoop-azure", "3.4.0-SNAPSHOT"},
		{"com.microsoft.azure:azure-storage", "7.0.1"},
		{"com.microsoft.azure:azure-keyvault-core", "1.0.0"},
		{"org.eclipse.jetty:jetty-util-ajax", "9.4.40.v20210413"},
		{"org.codehaus.jackson:jackson-mapper-asl", "1.9.13"},
		{"org.codehaus.jackson:jackson-core-asl", "1.9.13"},
		{"org.apache.hadoop:hadoop-azure-datalake", "3.4.0-SNAPSHOT"},
		{"com.microsoft.azure:azure-data-lake-store-sdk", "2.3.9"},
		{"org.apache.hadoop:hadoop-openstack", "3.4.0-SNAPSHOT"},
		{"org.apache.httpcomponents:httpcore", "4.4.13"},
		{"com.fasterxml.jackson.core:jackson-annotations", "2.10.5"},
		{"org.apache.hadoop:hadoop-cos", "3.4.0-SNAPSHOT"},
		{"com.qcloud:cos_api-bundle", "5.6.19"},
		{"org.apache.hadoop:hadoop-huaweicloud", "3.4.0-SNAPSHOT"},
		{"com.huaweicloud:esdk-obs-java", "3.20.4.2"},
		{"com.jamesmurty.utils:java-xmlbuilder", "1.2"},
		{"com.squareup.okhttp3:okhttp", "3.14.2"},
		{"org.apache.logging.log4j:log4j-core", "2.12.0"},
		{"org.apache.logging.log4j:log4j-api", "2.12.0"},
	}
	MavenNone = []types.Library{}

	MavenClassifier = []types.Library{
		{"org.springframework:spring-jcl", "5.0.1.RELEASE"},
		{"org.springframework:spring-core", "5.0.1.RELEASE"},
	}
)
