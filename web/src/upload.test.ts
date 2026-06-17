import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { uploadForm } from "./api"

class FakeXHR {
  upload = { onprogress: null as null | ((e: any) => void) }
  status = 0
  responseText = ""
  onload: null | (() => void) = null
  onerror: null | (() => void) = null
  _headers: Record<string, string> = {}
  withCredentials = false
  open() {}
  setRequestHeader(k: string, v: string) { this._headers[k] = v }
  send() {
    this.upload.onprogress?.({ lengthComputable: true, loaded: 5, total: 10 })
    this.status = 200
    this.responseText = JSON.stringify({ accounts: 3 })
    this.onload?.()
  }
}

beforeEach(() => { vi.stubGlobal("XMLHttpRequest", FakeXHR as unknown as typeof XMLHttpRequest) })
afterEach(() => { vi.unstubAllGlobals() })

describe("uploadForm", () => {
  it("reports progress and resolves the parsed body", async () => {
    const seen: number[] = []
    const body = await uploadForm<{ accounts: number }>("/upload", new FormData(), "csrf", (loaded, total) => seen.push(loaded / total))
    expect(seen).toEqual([0.5])
    expect(body.accounts).toBe(3)
  })
})
