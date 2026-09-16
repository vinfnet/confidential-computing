"""Localhost-only, single-process Qwen inference service for Citizen Help."""

from __future__ import annotations

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from citizen_help import (
    MODEL_ID,
    build_messages,
    model_metadata,
    sanitize_output,
    validate_question,
)

LOGGER = logging.getLogger('citizen-help-llm')
HOST = '127.0.0.1'
PORT = int(os.environ.get('CITIZENHELP_PORT', '8010'))
MODEL_PATH = os.environ.get('CITIZENHELP_MODEL_PATH', MODEL_ID)
MAX_BODY_BYTES = 32 * 1024
_model = None
_tokenizer = None
_torch = None


def load_model() -> None:
    global _model, _tokenizer, _torch
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    if not torch.cuda.is_available():
        raise RuntimeError('Citizen Help requires CUDA; CPU inference is disabled.')
    device_name = torch.cuda.get_device_name(0)
    if 'H100' not in device_name.upper():
        raise RuntimeError(f'Citizen Help requires an NVIDIA H100; found {device_name}.')
    _tokenizer = AutoTokenizer.from_pretrained(
        MODEL_PATH,
        local_files_only=True,
        revision=os.environ.get('CITIZENHELP_MODEL_REVISION'),
    )
    _model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=torch.bfloat16,
        device_map={'': 'cuda:0'},
        local_files_only=True,
        revision=os.environ.get('CITIZENHELP_MODEL_REVISION'),
    )
    _model.eval()
    _torch = torch
    LOGGER.info('Loaded %s on %s in bfloat16', MODEL_ID, device_name)


def generate_answer(question: str, records: list[dict[str, Any]]) -> str:
    if _model is None or _tokenizer is None or _torch is None:
        raise RuntimeError('Citizen Help model is not ready.')
    messages = build_messages(question, records)
    prompt = _tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
    )
    inputs = _tokenizer([prompt], return_tensors='pt').to('cuda:0')
    with _torch.inference_mode():
        output_ids = _model.generate(
            **inputs,
            max_new_tokens=240,
            do_sample=False,
            repetition_penalty=1.05,
            pad_token_id=_tokenizer.eos_token_id,
        )
    generated = output_ids[0][inputs.input_ids.shape[1]:]
    return sanitize_output(_tokenizer.decode(generated, skip_special_tokens=True))


def _json_response(handler: BaseHTTPRequestHandler, payload: dict[str, Any], status: int = 200) -> None:
    body = json.dumps(payload, ensure_ascii=True).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(body)))
    handler.send_header('Cache-Control', 'no-store')
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = 'CitizenHelpLLM/1.0'

    def log_message(self, format: str, *args: Any) -> None:
        LOGGER.info('%s - %s', self.address_string(), format % args)

    def do_GET(self) -> None:
        if self.path == '/health':
            _json_response(self, {'status': 'ready' if _model is not None else 'unavailable'})
            return
        if self.path == '/metadata':
            _json_response(self, model_metadata('cuda:0'))
            return
        _json_response(self, {'error': 'not found'}, 404)

    def do_POST(self) -> None:
        if self.path != '/generate':
            _json_response(self, {'error': 'not found'}, 404)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > MAX_BODY_BYTES:
                raise ValueError('Request body is too large or empty.')
            payload = json.loads(self.rfile.read(length))
            question = validate_question(payload.get('question'))
            records = payload.get('records')
            if not isinstance(records, list) or len(records) > 5:
                raise ValueError('A bounded registry context is required.')
            answer = generate_answer(question, records)
            _json_response(self, {'answer': answer, 'model': model_metadata('cuda:0')})
        except PermissionError as error:
            _json_response(self, {'answer': str(error), 'blocked': True}, 200)
        except (ValueError, TypeError) as error:
            _json_response(self, {'error': str(error)}, 400)
        except Exception:
            LOGGER.exception('Citizen Help generation failed')
            _json_response(self, {'error': 'Citizen Help is temporarily unavailable.'}, 503)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    load_model()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == '__main__':
    main()
