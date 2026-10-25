import Foundation
import AVFoundation

/// Voice messages: 16 kHz mono 16-bit PCM in a WAV container, built and played entirely in memory.
/// Nothing is recorded to a file; AVAudioEngine delivers buffers straight from the microphone.
enum WAV {
    static let sampleRate = 16_000
    static let headerSize = 44

    static func wrap(pcm: Data, sampleRate: Int = WAV.sampleRate) -> Data {
        var out = Data(capacity: headerSize + pcm.count)
        func u32(_ value: UInt32) { var v = value.littleEndian; withUnsafeBytes(of: &v) { out.append(contentsOf: $0) } }
        func u16(_ value: UInt16) { var v = value.littleEndian; withUnsafeBytes(of: &v) { out.append(contentsOf: $0) } }
        out.append(contentsOf: Array("RIFF".utf8)); u32(UInt32(36 + pcm.count)); out.append(contentsOf: Array("WAVE".utf8))
        out.append(contentsOf: Array("fmt ".utf8)); u32(16); u16(1); u16(1); u32(UInt32(sampleRate))
        u32(UInt32(sampleRate * 2)); u16(2); u16(16)
        out.append(contentsOf: Array("data".utf8)); u32(UInt32(pcm.count))
        out.append(pcm)
        return out
    }

    static func isValid(_ data: Data) -> Bool {
        guard data.count > headerSize else { return false }
        let start = data.startIndex
        return data[start..<start + 4] == Data("RIFF".utf8) && data[start + 8..<start + 12] == Data("WAVE".utf8)
    }

    /// Duration from the header's byte rate, so a different sender format still shows a sensible length.
    static func duration(of data: Data) -> TimeInterval {
        guard isValid(data) else { return 0 }
        let start = data.startIndex
        let byteRate = data[start + 28..<start + 32].enumerated().reduce(0) { $0 | (Int($1.element) << (8 * $1.offset)) }
        guard byteRate > 0 else { return 0 }
        return TimeInterval(data.count - headerSize) / TimeInterval(byteRate)
    }
}

/// Converts microphone buffers to 16 kHz mono Int16 and collects them. Runs on the audio thread, so it
/// is a plain class with its own lock instead of being tied to the main actor.
final class PCMCollector: @unchecked Sendable {
    private let converter: AVAudioConverter
    private let target: AVAudioFormat
    private let maxBytes: Int
    private let lock = NSLock()
    private var data = Data()

    init(converter: AVAudioConverter, target: AVAudioFormat, maxBytes: Int) {
        self.converter = converter
        self.target = target
        self.maxBytes = maxBytes
        data.reserveCapacity(maxBytes)
    }

    func consume(_ buffer: AVAudioPCMBuffer) {
        let ratio = target.sampleRate / buffer.format.sampleRate
        let capacity = AVAudioFrameCount(Double(buffer.frameLength) * ratio + 64)
        guard let output = AVAudioPCMBuffer(pcmFormat: target, frameCapacity: capacity) else { return }
        var supplied = false
        var error: NSError?
        let status = converter.convert(to: output, error: &error) { _, inputStatus in
            if supplied { inputStatus.pointee = .noDataNow; return nil }
            supplied = true
            inputStatus.pointee = .haveData
            return buffer
        }
        guard status != .error, output.frameLength > 0, let channel = output.int16ChannelData else { return }
        let bytes = Data(bytes: channel[0], count: Int(output.frameLength) * 2)
        lock.lock()
        if data.count < maxBytes { data.append(bytes.prefix(maxBytes - data.count)) }
        lock.unlock()
    }

    var byteCount: Int { lock.lock(); defer { lock.unlock() }; return data.count }
    func take() -> Data { lock.lock(); defer { lock.unlock() }; let result = data; data = Data(); return result }
}

@MainActor
final class VoiceRecorder: ObservableObject {
    static let maxDuration: TimeInterval = 90
    static let minDuration: TimeInterval = 0.6
    @Published private(set) var recording = false
    @Published private(set) var elapsed: TimeInterval = 0
    private let engine = AVAudioEngine()
    private var collector: PCMCollector?
    private var timer: Timer?
    /// Called once when the 90-second limit is reached; the owner then stops and sends.
    var onLimit: (() -> Void)?

    static var maxBytes: Int { Int(maxDuration) * WAV.sampleRate * 2 }

    func requestPermission() async -> Bool { await AVAudioApplication.requestRecordPermission() }

    func start() throws {
        guard !recording else { return }
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playAndRecord, mode: .spokenAudio, options: [.defaultToSpeaker, .allowBluetooth])
        try session.setActive(true)
        let input = engine.inputNode
        let inputFormat = input.outputFormat(forBus: 0)
        guard inputFormat.sampleRate > 0, inputFormat.channelCount > 0,
              let target = AVAudioFormat(commonFormat: .pcmFormatInt16, sampleRate: Double(WAV.sampleRate), channels: 1, interleaved: true),
              let converter = AVAudioConverter(from: inputFormat, to: target) else {
            try? session.setActive(false, options: .notifyOthersOnDeactivation)
            throw GhostError.unavailable
        }
        let collector = PCMCollector(converter: converter, target: target, maxBytes: Self.maxBytes)
        input.installTap(onBus: 0, bufferSize: 4096, format: inputFormat) { @Sendable buffer, _ in collector.consume(buffer) }
        engine.prepare()
        do { try engine.start() } catch {
            input.removeTap(onBus: 0)
            try? session.setActive(false, options: .notifyOthersOnDeactivation)
            throw error
        }
        self.collector = collector
        elapsed = 0
        recording = true
        let timer = Timer(timeInterval: 0.2, repeats: true) { [weak self] _ in Task { @MainActor in self?.tick() } }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    private func tick() {
        guard recording, let collector else { return }
        elapsed = TimeInterval(collector.byteCount) / TimeInterval(WAV.sampleRate * 2)
        if elapsed >= Self.maxDuration { onLimit?() }
    }

    /// Stops and returns the WAV, or nil when the recording was too short.
    func stop() -> Data? {
        guard recording else { return nil }
        engine.inputNode.removeTap(onBus: 0)
        engine.stop()
        timer?.invalidate(); timer = nil
        recording = false
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        let pcm = collector?.take() ?? Data()
        collector = nil
        elapsed = 0
        guard TimeInterval(pcm.count) / TimeInterval(WAV.sampleRate * 2) >= Self.minDuration else { return nil }
        return WAV.wrap(pcm: pcm)
    }

    func cancel() { _ = stop() }
}

@MainActor
final class VoicePlayer: NSObject, ObservableObject, AVAudioPlayerDelegate {
    @Published private(set) var playingID: UUID?
    @Published private(set) var progress: Double = 0
    private var player: AVAudioPlayer?
    private var timer: Timer?

    func toggle(_ id: UUID, data: Data) {
        if playingID == id { stop(); return }
        stop()
        do {
            try AVAudioSession.sharedInstance().setCategory(.playback, mode: .spokenAudio)
            try AVAudioSession.sharedInstance().setActive(true)
            let player = try AVAudioPlayer(data: data, fileTypeHint: AVFileType.wav.rawValue)
            player.delegate = self
            guard player.play() else { return }
            self.player = player
            playingID = id
            progress = 0
            let timer = Timer(timeInterval: 0.1, repeats: true) { [weak self] _ in Task { @MainActor in self?.update() } }
            RunLoop.main.add(timer, forMode: .common)
            self.timer = timer
        } catch { stop() }
    }

    private func update() {
        guard let player, player.duration > 0 else { return }
        progress = min(1, player.currentTime / player.duration)
    }

    func stop() {
        player?.stop(); player = nil
        timer?.invalidate(); timer = nil
        playingID = nil; progress = 0
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    nonisolated func audioPlayerDidFinishPlaying(_ player: AVAudioPlayer, successfully flag: Bool) {
        Task { @MainActor in self.stop() }
    }
}
