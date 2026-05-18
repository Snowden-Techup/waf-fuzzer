from __future__ import annotations

from urllib.parse import urlsplit

from modules.base_module import BaseModule
from modules.file_upload.analyzer import detect_file_upload
from modules.file_upload.form_helpers import select_upload_target_parameters
from modules.file_upload.payloads import FilePayload, get_file_upload_payloads
from modules.file_upload.verifier import EXECUTION_MARKER, extract_dynamic_verify_urls


class FileUploadModule(BaseModule):
    def __init__(self):
        super().__init__("File Upload")

    def get_payloads(self):
        return get_file_upload_payloads()

    def get_target_parameters(self, surface, parameters):
        """
        Run only where upload-like behavior is plausible.
        """
        method = str(getattr(getattr(surface, "method", ""), "value", surface.method)).upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return ()
        parameter_list = [str(param) for param in parameters]
        return select_upload_target_parameters(surface, parameter_list)

    def analyze(self, response, payload, elapsed_time, original_res=None, requester=None) -> bool:
        is_vuln, _ = detect_file_upload(response=response, payload=payload)
        return is_vuln

    async def verify(
        self,
        *,
        session,
        surface,
        parameter,
        payload,
        response,
        baseline_response=None,
    ) -> bool:
        """
        Stage 2 verification: request uploaded file and confirm marker execution.
        """
        if not isinstance(payload, FilePayload):
            return False

        split = urlsplit(surface.url)
        base = f"{split.scheme}://{split.netloc}"
        seen: set[str] = set()
        verify_urls: list[str] = []

        dynamic_urls = extract_dynamic_verify_urls(
            base_url=base,
            response_text=getattr(response, "text", "") or "",
            filename=payload.filename,
        )
        for dynamic_url in dynamic_urls:
            if dynamic_url in seen:
                continue
            seen.add(dynamic_url)
            verify_urls.append(dynamic_url)

        if not verify_urls:
            return False

        request_kwargs = {}
        headers = getattr(surface, "headers", None) or {}
        cookies = getattr(surface, "cookies", None) or {}
        if headers:
            request_kwargs["headers"] = headers
        if cookies:
            request_kwargs["cookies"] = cookies

        for verify_url in verify_urls:
            try:
                async with session.get(verify_url, **request_kwargs) as verify_response:
                    body = await verify_response.text(errors="replace")
            except Exception:
                continue

            if EXECUTION_MARKER not in body:
                continue
            if "<?php" in body.lower() or "&lt;?php" in body.lower():
                continue

            return True

        return False
