package org.cisecurity.ietf.sacm

import groovy.xml.XmlUtil
import groovyx.net.http.RESTClient
import org.cisecurity.assessor.util.AssessorUtilities
import org.jivesoftware.smack.XMPPException
import org.jivesoftware.smackx.pubsub.ItemPublishEvent
import org.jivesoftware.smackx.pubsub.LeafNode
import org.jivesoftware.smackx.pubsub.PubSubManager
import org.jivesoftware.smackx.pubsub.listener.ItemEventListener
import org.slf4j.LoggerFactory

/**
 * Created by wmunyan on 2/26/2018.
 */
class ContentSubscription {
	def log = LoggerFactory.getLogger(ContentSubscription.class)

	final String NODE_NAME = "AssessmentContent"

	String jid
	ResultsPublisher pub
	LeafNode content

	/**
	 * Subscribe to the content node
	 * @param psm
	 * @return
	 */
	def subscribe(PubSubManager psm) {
		log.info "Attempting to retrieve topic --> ${NODE_NAME}"

		try {
			content = psm.getLeafNode(NODE_NAME)

			log.info "Found topic --> ${NODE_NAME}"

			content.addItemEventListener(new AssessmentExecutor(pub: pub))

			def subs = content.subscriptions
			def found = subs.find { s -> s.jid == jid }
			if (!found) {
				log.info "Subscribing JID --> ${jid} to topic --> ${NODE_NAME}"
				content.subscribe(jid)
			} else {
				log.info "JID --> ${jid} is already subscribed to topic --> ${NODE_NAME}"
			}
		} catch (XMPPException.XMPPErrorException e) {
			log.error "Exception when retrieving topic --> ${NODE_NAME}", e
		}
	}
}

class AssessmentExecutor implements ItemEventListener {
	def log = LoggerFactory.getLogger(AssessmentExecutor.class)

	ResultsPublisher pub

	@Override
	void handlePublishedItems(ItemPublishEvent items) {
		def assessorQueue = []

		log.info "Entering published item handler..."

		items.items.eachWithIndex { item, i ->
			def itemNode = AssessorUtilities.instance.getParser().parseText(item.toXML())
			def getUrlNode = itemNode.children()[0]
			def url = getUrlNode.text()

			def ifp = "C:\\Temp\\XMPP-Item-${i+1}.xml"
			log.info "Writing File --> ${ifp}"

			def rest = new RESTClient(url)
			rest.ignoreSSLIssues()

			def emptyHeaders = [:]
			emptyHeaders."Accept" = 'application/xml'
			emptyHeaders."Prefer" = 'test'

			def response = rest.get(headers: emptyHeaders)

			log.info("Status: ${response.status}")
			if (response.data) {
				//println("Content Type: " + response.contentType)
				log.info("Headers: ${response.getAllHeaders()}")
				def x = new String(response.data.bytes)
				new File(ifp).withWriter { w -> w.write x }

				assessorQueue << ifp
			}

//			def payloadBasename = AssessorUtilities.instance.getElementBasename(payloadNode.name())
//			if (payloadBasename == "data-stream-collection") {
//				new File(ifp).withWriter { w ->
//					w.write XmlUtil.serialize(payloadNode)
//				}
//				assessorQueue << ifp
//			} else {
//				log.error "Invalid payload on topic -- ${payloadBasename}"
//			}
		}

		new AssessmentWrapper(pub: pub).execute(assessorQueue)
	}
}
