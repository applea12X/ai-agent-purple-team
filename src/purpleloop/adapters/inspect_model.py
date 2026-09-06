from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from inspect_ai.model import ChatMessage, GenerateConfig, ModelAPI, ModelOutput, modelapi
from inspect_ai.tool import ToolChoice, ToolInfo

from purpleloop.adapters.offline_model import OfflineModelStore, OfflineResponseMissing


class OfflineModelAPI(ModelAPI):
    def __init__(
        self,
        model_name: str,
        base_url: str | None = None,
        api_key: str | None = None,
        config: GenerateConfig | None = None,
        **model_args: Any,
    ) -> None:
        if base_url or api_key or model_name != "offline":
            raise ValueError("offline provider accepts only the offline model and no endpoint")
        super().__init__(model_name, config=config or GenerateConfig())
        self.store = OfflineModelStore(Path(model_args["fixture_path"]))
        self.profile = str(model_args.get("profile", "deterministic"))

    async def generate(
        self,
        input: list[ChatMessage],
        tools: list[ToolInfo],
        tool_choice: ToolChoice,
        config: GenerateConfig,
    ) -> ModelOutput:
        if (
            tools
            or len(input) != 1
            or input[0].role != "user"
            or not isinstance(input[0].content, str)
        ):
            raise OfflineResponseMissing("offline request shape mismatch")
        request = json.loads(input[0].content)
        if not isinstance(request, dict):
            raise OfflineResponseMissing("offline request must be an exact object")
        response = self.store.complete(model=self.model_name, profile=self.profile, request=request)
        return ModelOutput.from_content(self.model_name, response.response)


@modelapi(name="purpleloop")
def offline_model() -> type[OfflineModelAPI]:
    return OfflineModelAPI
