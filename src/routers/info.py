from fastapi import APIRouter

router = APIRouter(
    tags=["Info"],
)

@router.get("/get")
@router.get("/version")
def version():
    return {"version": "0.0.1"}
 