# Integration: PoC to enable XMPP integrations between SACM Components
An architecture proposal has been made to the SACM working group, and this repository holds proof of concept code for the scenario described below. The proposed architecture looks something like this:

![Proposed Architecture](https://raw.githubusercontent.com/CISecurity/Integration/master/docs/img/mandm-arch.png)

# Scenario 1: New Configuration Assessment Available

![Configuration Assessment Scenario](https://raw.githubusercontent.com/CISecurity/Integration/master/docs/img/ietf-101-hackathon%202.png)

1. New configuration assessment content is published (via mockup policy source)
2. Configuration assessment publisher interface puts new content "on the grid"
3. Configuration assessment subscriber receives new content and passes to the assessment engine
4. Assessment engine interprets new content
5. Assessment engine collects data
6. Assessment engine evaluates data
7. Configuration assessment results are put "on the grid"
8. Configuration assessment results subscriber receives new results
9. Results subscriber imports results

We hope to largely configure (using [Openfire](https://www.igniterealtime.org/projects/openfire/)) an XMPP-Grid with little or no additional coding (per the latest [XMPP-Grid specification](https://datatracker.ietf.org/doc/draft-ietf-mile-xmpp-grid/)). Additionally, we intend to use an existing assessment engine and results aggregator ([CIS-CAT Pro](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro/) from CIS). This means we'll be primarily responsible for coding the following components:

1. A mocked content publication engine
2. Configuration assessment content publishing component
3. Configuration assessment content subscriber component
4. Configuration assessment results publishing component
5. Configuration assessment results subscriber component

# Follow-on Ideas/Learnings

This flow has been a relatively simple pub/sub model that requires, for out-of-the-box interoperability, some prior understanding of the nodes that are available and what we can expect to go across them. We have not yet explored what the interface ought to be for watching a given configuration item, as one example, nor have we looked at what a fully-specified interface would look like for getting the latest applicable guidance from the policy side.

In face, we have identified that relying only upon the XMPP-grid draft as it has been submitted in MILE is insufficient for our needs in SACM. Our hypothesis looked at what might work for a core messaging infrastructure, now we need to focus on the interfaces for each component.

* Interface to local state assessment policy storage
  * List available content
    * By type (i.e. security purpose)
    * By platform
    * By type and platform
    * By name
    * By date or date range
    * By version
    * By * (some extension that might be proprietary)
    * Others?
* Interface to collector
  * Ad hoc assessment (on-demand processing)
  * State item watch actions (watch, stop watching, etc.)
  * Mandatory periodic reporting
* Interface to evaluator
* Others?

From this type of exploration we hope to arrive at a natural way of describing the abstract interfaces required for each component, and to specify an XMPP binding for that interface. We will also need to specify data models for certain uses and likely the semantics behind the specific "capabilities".

We've also learned a lot more about the possibilities with XMPP and it's set of extensions (XEPs). Specifically, we see some promise in several, if not most, of the following XEPs:

* [Entity Capabilities: XEP-0115](https://xmpp.org/extensions/xep-0115.html) - May be used to express the specific capabilities that a particular client embodies.
* [Form Discovery and Publishing: XEP-0346](https://xmpp.org/extensions/xep-0346.html) - May be used for datastream examples requiring some expression of a request followed by an expected response.
* [Ad Hoc Commands: XEP-0050](https://xmpp.org/extensions/xep-0050.html) - May be usable for simple orchestration (i.e. "do assessment").
* [File Repository and Sharing: XEP-0214](https://xmpp.org/extensions/xep-0214.html) - Appears to be needed for handling large amounts of data (if not fragmenting)
* [Publishing Stream Initiation Requests: XEP-0137](https://xmpp.org/extensions/xep-0137.html) - Provides ability to stream information between two XMPP entities.
* [PubSub Collection Nodes: XEP-0248](https://xmpp.org/extensions/xep-0248.html) - Nested topics for specialization to the leaf node level.
* [Security Labels In Pub/Sub: XEP-0314](https://xmpp.org/extensions/xep-0314.html) - Enables tagging data with classification categories.
* [PubSub Chaining: XEP-0253](https://xmpp.org/extensions/xep-0253.html) - Federation of publishing nodes enabling a publish node of one server to be a subscriber to a publishing node of another server
[Easy User Onboarding: XEP-0253](https://xmpp.org/extensions/xep-0253.html) - Simplified client registration

# Possibilities For The Future

We'd like to try to get an external policy source federated with a local policy source, which might look something like this.
![Next Steps](https://raw.githubusercontent.com/CISecurity/Integration/master/docs/img/01-next.png)

Then, we will look at what other XMPP extensions (see previous section) might be able to do for us for specific workflows (TBD).
![Possible XMPP Extensions](https://raw.githubusercontent.com/CISecurity/Integration/master/docs/img/02-possible-xmpp-extensions.png)

We also recognize the distinct possibility that agents could be direct participants in an XMPP-grid.
![Agents as XMPP Clients](https://raw.githubusercontent.com/CISecurity/Integration/master/docs/img/03-xmpp-as-agent.png)

And, from that thought process XMPP presence with capabilities (features and items) naturally follow.
![XMPP Presence for Agents](https://raw.githubusercontent.com/CISecurity/Integration/master/docs/img/04-presense-for-endpoints.png)
