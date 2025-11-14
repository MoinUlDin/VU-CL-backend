# # utils/llm.py
# import json
# from django.conf import settings
# import openai

# openai.api_key = settings.OPENAI_API_KEY

# def generate_lesson_plan(
#     grade: str,
#     subject: str,
#     topic: str,
#     duration_minutes: int = 40,
#     language: str = "English"
# ) -> dict:
#     prompt = f"""
# You are an experienced elementary school teacher in Punjab, Pakistan.
# Generate a classroom-ready lesson plan in JSON only (no extra commentary) for:
# grade: {grade}
# subject: {subject}
# topic: {topic}
# duration: {duration_minutes} minutes
# language: {language}

# Constraints: government school environment, few resources (chalkboard, textbook), class size ~35, practical low-cost activity, clear timing for each step.
# Follow the JSON schema described earlier.
# """
#     try:
#         resp = openai.ChatCompletion.create(
#             model="GPT-5",   # or change to the model you have access to
#             messages=[
#                 {"role": "system", "content": "You are a helpful teacher that outputs JSON only."},
#                 {"role": "user", "content": prompt},
#             ],
#             max_tokens=2000,
#             temperature=0.2,
#         )

#         text = resp["choices"][0]["message"]["content"].strip()

#         # sometimes model adds backticks or commentary; try to extract JSON
#         # naive cleanup:
#         if text.startswith("```"):
#             # remove code fence
#             text = "\n".join(text.splitlines()[1:-1])
#         # parse JSON
#         lesson = json.loads(text)
#         return lesson
#     except json.JSONDecodeError:
#         # fallback: return raw text so you can debug
#         return {"error": "invalid json", "raw": text}
#     except Exception as e:
#         return {"error": str(e)}
