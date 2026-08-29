

public struct SecurityQuestion: Sendable, Hashable, Codable {
    public var question: String
    public var answer: String

    public init(question: String, answer: String) {
        self.question = question
        self.answer = answer
    }
}
