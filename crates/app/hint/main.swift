// peersig-hint: points out, in the review, the names that could say
// something sensitive about the person, with Apple's on-device language
// model (Foundation Models, part of Apple Intelligence, macOS 26 and
// later). The PeerSig app runs it with the applications and server names
// of the week; the review shows what it flags first, next to what the
// list of sensitive words flags (crates/proto/data/sensitive.txt).
//
// The model runs on this Mac: nothing is sent anywhere, and this program
// opens no connection. It only reads names on its input and answers on its
// output:
//
//   in:  {"entries": ["Application: Nextcloud (com.nextcloud.desktopclient)",
//                     "Server name: cloud.example.org", ...]}
//   out: {"status": "ok", "flags": [{"entry": 1, "reason": "a personal, family or small association server"}]}
//        {"status": "unavailable", "detail": "Apple Intelligence is off"}
//
// Entries are numbered from 0. Built by crates/app/hint/build.sh.

import Foundation

#if canImport(FoundationModels)
import FoundationModels
#endif

struct Request: Decodable {
    let entries: [String]
}

struct Flag: Encodable {
    let entry: Int
    let reason: String
}

struct Reply: Encodable {
    var status: String
    var detail: String?
    var flags: [Flag] = []
}

/// What the model may say an entry is. The first four are ordinary; the
/// others are worth a second look. The model answers better with ordinary
/// kinds to choose from than with a yes or no (tested on a sample of real
/// names: none of 40 ordinary ones flagged).
let ordinary = [
    "operating system or software service",
    "office, mail, chat or meeting service",
    "cloud, hosting, content delivery, analytics or advertising",
    "website or online service of a company or university",
]
let sensitive = [
    "health",
    "sexuality or dating",
    "religion",
    "politics or trade union",
    "ethnicity",
    "money troubles or gambling",
    "crypto-currencies",
    "legal or immigration",
    "job search",
    "a personal, family or small association server",
]

let instructions = """
    You help a person check a list before it is shared with a research study about network traffic. \
    Each entry is an application on their computer, or the name of an internet server an application connected to. \
    Say what the entry is, then what kind of entry it is. \
    A personal, family or small association server is one named after a person, a family or a small group, \
    not a company's.
    """

#if canImport(FoundationModels)
@available(macOS 26.0, *)
@Generable
struct Kind {
    @Guide(description: "What it is, in a few words")
    var what: String
    @Guide(description: "What kind of entry it is", .anyOf(ordinary + sensitive))
    var kind: String
}

/// One entry, in a session of its own: the model answers each better
/// alone than in a list. An entry the model refuses to look at (its
/// guardrails) is flagged: it found it sensitive.
@available(macOS 26.0, *)
func check(_ model: SystemLanguageModel, _ entry: String) async throws -> String? {
    let session = LanguageModelSession(model: model, instructions: instructions)
    // Greedy: the same answer every time. Xcode 27 renamed `sampling` to
    // `samplingMode`, which Xcode 26 (CI's) does not know.
    var options = GenerationOptions()
    options.sampling = .greedy
    do {
        let k = try await session.respond(to: "Entry: " + entry, generating: Kind.self, options: options).content
        return sensitive.contains(k.kind) ? k.kind : nil
    } catch let e as LanguageModelSession.GenerationError {
        switch e {
        case .guardrailViolation, .refusal:
            return "the model would not look at it"
        default:
            throw e
        }
    }
}

@available(macOS 26.0, *)
func run(_ entries: [String]) async -> Reply {
    // The on-device model only (never Private Cloud Compute): nothing
    // leaves this Mac.
    let model = SystemLanguageModel.default
    switch model.availability {
    case .available:
        break
    case .unavailable(.deviceNotEligible):
        return Reply(status: "unavailable", detail: "this Mac cannot run Apple Intelligence")
    case .unavailable(.appleIntelligenceNotEnabled):
        return Reply(status: "unavailable", detail: "Apple Intelligence is off (System Settings)")
    case .unavailable(.modelNotReady):
        return Reply(status: "unavailable", detail: "Apple Intelligence is still getting ready")
    case .unavailable(let other):
        return Reply(status: "unavailable", detail: "Apple Intelligence is not available (\(other))")
    }
    var flags: [Flag] = []
    for (i, entry) in entries.enumerated() {
        do {
            if let why = try await check(model, entry) {
                flags.append(Flag(entry: i, reason: why))
            }
        } catch {
            return Reply(status: "error", detail: "\(error)", flags: flags)
        }
    }
    return Reply(status: "ok", flags: flags)
}
#endif

func answer(_ reply: Reply) {
    let data = (try? JSONEncoder().encode(reply)) ?? Data(#"{"status":"error"}"#.utf8)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

@main
struct Main {
    static func main() async {
        let input = FileHandle.standardInput.readDataToEndOfFile()
        guard let request = try? JSONDecoder().decode(Request.self, from: input) else {
            answer(Reply(status: "error", detail: "bad request"))
            exit(2)
        }
        #if canImport(FoundationModels)
        if #available(macOS 26.0, *) {
            answer(await run(request.entries))
            return
        }
        #endif
        answer(Reply(status: "unavailable", detail: "Apple Intelligence needs macOS 26 or later"))
    }
}
