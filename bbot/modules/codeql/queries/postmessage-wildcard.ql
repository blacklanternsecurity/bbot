/**
 * @name Data posted to any origin
 * @description The page posts data it computes with postMessage(data, "*"), so whichever page framed or opened it
 *              can read it.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 3.1
 * @precision medium
 * @id bbot/postmessage-wildcard
 * @tags security
 *       external/cwe/cwe-201
 */

import javascript
import PostMessage

from WildcardPostMessage call, DataFlow::Node data
where
  postsData(call, data) and
  not leaks(call, _)
select call, "$@ is posted to any origin.", data, "Data the page computes"
