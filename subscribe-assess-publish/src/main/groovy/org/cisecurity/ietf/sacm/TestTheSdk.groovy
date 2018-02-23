package org.cisecurity.ietf.sacm

import org.jivesoftware.smack.AbstractXMPPConnection
import org.jivesoftware.smack.ConnectionConfiguration
import org.jivesoftware.smack.tcp.XMPPTCPConnection
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration
import org.jivesoftware.smackx.pubsub.AccessModel
import org.jivesoftware.smackx.pubsub.ConfigureForm
import org.jivesoftware.smackx.pubsub.Item
import org.jivesoftware.smackx.pubsub.LeafNode
import org.jivesoftware.smackx.pubsub.PayloadItem
import org.jivesoftware.smackx.pubsub.PubSubManager
import org.jivesoftware.smackx.pubsub.PublishModel
import org.jivesoftware.smackx.pubsub.SimplePayload
import org.jivesoftware.smackx.xdata.packet.DataForm

/**
 * Created by wmunyan on 2/19/2018.
 */
class TestTheSdk {
	static void main(String[] args) {
		println "Loading properties..."

		Properties properties = new Properties()
		properties.load(getClass().getResourceAsStream("/conn.properties"))

		println "Configuring XMPP connection..."
		XMPPTCPConnectionConfiguration config = XMPPTCPConnectionConfiguration.builder()
			.setUsernameAndPassword(properties.user, properties.password)
			.setXmppDomain(properties.xmppdomain)
			.setHost(properties.host)
			.setPort(Integer.parseInt(properties.port))
			.setSecurityMode(ConnectionConfiguration.SecurityMode.disabled)
			.build()

		println "Connecting to XMPP server as user ${properties.user}..."
		AbstractXMPPConnection conn2 = new XMPPTCPConnection(config)
		conn2.connect().login()

		def b

		println "Getting the topic..."

		// Create a pubsub manager using an existing XMPPConnection
		PubSubManager mgr = PubSubManager.getInstance(conn2)
		def leaf = mgr.getLeafNode("PayloadNode")

		// Create the node
//		ConfigureForm form = new ConfigureForm(DataForm.Type.submit)
//		form.setAccessModel(AccessModel.open)
//		form.setDeliverPayloads(true)
//		form.setNotifyRetract(true)
//		form.setPersistentItems(true)
//		form.setPublishModel(PublishModel.open)
//		LeafNode leaf = mgr.createNode("PayloadNode", form)

		// Open the file...
		def f =
			new File(
				"C:\\_Development\\Projects\\CISCAT\\content_development\\" +
				"benchmarks_scap\\CIS_Microsoft_Internet_Explorer_11_Benchmark_v1.0.0-collection.xml")
		def collectionNode = new XmlParser().parse(f)
		def collectionId = collectionNode.@id.toString()

		println "Constructing payload for collection id --> ${collectionId}..."

		def sp = new SimplePayload(
			"data-stream-collection",
			"http://scap.nist.gov/schema/scap/source/1.2",
			f.text)

		println "Payload size is ${f.length()}..."

		def pi = new PayloadItem(collectionId, sp)

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

		println "Publishing payload to topic..."

		// Publish an Item with payload
		leaf.send(pi)

		println "Disconnecting from XMPP server..."

		conn2.disconnect()
	}
}
