// Self-contained test runner. No XCTest/Testing (absent under Command Line Tools).
// Run: `SE_SSH_MOCK=1 swift run sod-tests`. Exits 0 on success, 1 on any failure.
//
// The wire suite is pure and always runs. The KeyStore and Agent suites need the
// mock backend (no Secure Enclave, no Touch ID) and so are compiled in only under
// SE_SSH_MOCK — a non-mock build still passes by skipping them.
import Foundation

let harness = Harness()
harness.runWireSuite()
runInstallSuite(harness)
runDoctorSuite(harness)
runCopyIdSuite(harness)
#if SE_SSH_MOCK
runKeyStoreSuite(harness)
runAgentSuite(harness)
#else
harness.note("SE_SSH_MOCK not defined — skipping KeyStore/Agent suites (build with SE_SSH_MOCK=1 to run them)")
#endif
harness.finishAndExit()
