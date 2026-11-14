/**
 * @name Sensitive data posted to any origin
 * @description The page posts its URL, cookies or storage with postMessage(data, "*"), so whichever page framed or
 *              opened it can read them, an OAuth code or token in the URL included.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @id bbot/postmessage-leak
 * @tags security
 *       external/cwe/cwe-201
 *       external/cwe/cwe-359
 */

import javascript
import PostMessage

from WildcardPostMessage call, DataFlow::Node source
where leaks(call, source)
select call, "$@ is posted to any origin.", source, "Data from the page's URL, cookies or storage"
