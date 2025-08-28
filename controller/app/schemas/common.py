# app/schemas/common.py
from pydantic import BaseModel
from typing import List, Any

class PaginationInfo(BaseModel):
    total_items: int
    total_pages: int
    current_page: int
    page_size: int
    has_next: bool
    has_previous: bool