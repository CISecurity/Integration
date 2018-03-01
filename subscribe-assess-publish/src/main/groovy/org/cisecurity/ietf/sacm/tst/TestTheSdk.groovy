package org.cisecurity.ietf.sacm.tst

import org.slf4j.LoggerFactory

/**
 * Testing
 * Created by wmunyan on 2/19/2018.
 */
class TestTheSdk {
	def log = LoggerFactory.getLogger(TestTheSdk.class)

	def tw

	static void main(String[] args) {
		if (args.length != 1) {
			println "Usage: TestTheSdk [filepath-to-publish]"
			System.exit(1)
		}
		def tts = new TestTheSdk()
		tts.init()
		tts.publishTest(args[0])
		//tts.subscribeTest()
		tts.teardown()
	}

	void init() {
		tw = new TopicWrapper(topicName: "AssessmentContent")
		tw.initialize()
		tw.retrieveOrCreateTopic()
	}

	void publishTest(def fp) {
		//def p = "C:\\_Development\\Projects\\CISCAT\\content_development\\benchmarks_scap"
		//def f = "CIS_Microsoft_Windows_10_Enterprise_Release_1607_Benchmark_v1.2.0-collection.xml"
		//def f = "CIS_Microsoft_Internet_Explorer_11_Benchmark_v1.0.0-collection.xml"

		tw.publishCollection(fp)
	}

	void subscribeTest() {
		tw.retrieveCollection()
	}

	void teardown() {
		log.info "Disconnecting from XMPP server..."
		tw.disconnect()
	}
}

//		def iodef = """<IODEF-Document version="2.00" xml:lang="en"
//            xmlns="urn:ietf:params:xml:ns:iodef-2.0"
//            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
//            xsi:schemaLocation=
//              "http://www.iana.org/assignments/xml-registry/
//               schema/iodef-2.0.xsd">
//            <Incident purpose="reporting" restriction="private">
//              <IncidentID name="csirt.example.com">492382</IncidentID>
//              <GenerationTime>2015-07-18T09:00:00-05:00</GenerationTime>
//              <Contact type="organization" role="creator">
//                <Email>
//                  <EmailTo>contact@csirt.example.com</EmailTo>
//                </Email>
//              </Contact>
//            </Incident>
//          </IODEF-Document>"""
//
//		def sp = new SimplePayload(
//			"IODEF-Document",
//			"urn:ietf:params:xml:ns:iodef-2.0",
//			iodef)
//		def pi = new PayloadItem("8bh1g27skbga47fh9wk7", sp)
