export type StreamSealErrorCode =
  | "INVALID_HEADER"
  | "UNSUPPORTED_VERSION"
  | "UNSUPPORTED_ALGORITHM"
  | "INVALID_CHUNK"
  | "AUTHENTICATION_FAILED"
  | "TRUNCATED_STREAM"
  | "RESOURCE_LIMIT"
  | "INVALID_KEY";

export class StreamSealError extends Error {
  readonly code: StreamSealErrorCode;

  constructor(code: StreamSealErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "StreamSealError";
    this.code = code;
  }
}

export class InvalidHeaderError extends StreamSealError {
  constructor(message: string, options?: ErrorOptions) {
    super("INVALID_HEADER", message, options);
    this.name = "InvalidHeaderError";
  }
}

export class UnsupportedVersionError extends StreamSealError {
  constructor(message: string, options?: ErrorOptions) {
    super("UNSUPPORTED_VERSION", message, options);
    this.name = "UnsupportedVersionError";
  }
}

export class UnsupportedAlgorithmError extends StreamSealError {
  constructor(message: string, options?: ErrorOptions) {
    super("UNSUPPORTED_ALGORITHM", message, options);
    this.name = "UnsupportedAlgorithmError";
  }
}

export class InvalidChunkError extends StreamSealError {
  constructor(message: string, options?: ErrorOptions) {
    super("INVALID_CHUNK", message, options);
    this.name = "InvalidChunkError";
  }
}

export class AuthenticationFailedError extends StreamSealError {
  constructor(message: string, options?: ErrorOptions) {
    super("AUTHENTICATION_FAILED", message, options);
    this.name = "AuthenticationFailedError";
  }
}

export class TruncatedStreamError extends StreamSealError {
  constructor(message: string, options?: ErrorOptions) {
    super("TRUNCATED_STREAM", message, options);
    this.name = "TruncatedStreamError";
  }
}

export class ResourceLimitError extends StreamSealError {
  constructor(message: string, options?: ErrorOptions) {
    super("RESOURCE_LIMIT", message, options);
    this.name = "ResourceLimitError";
  }
}

export class InvalidKeyError extends StreamSealError {
  constructor(message: string, options?: ErrorOptions) {
    super("INVALID_KEY", message, options);
    this.name = "InvalidKeyError";
  }
}
