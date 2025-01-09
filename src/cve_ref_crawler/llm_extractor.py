import os
from dotenv import load_dotenv, dotenv_values
import google.generativeai as genai
from pathlib import Path
from typing import Optional
import logging
from .utils.logging_utils import setup_logging
from config import LOG_CONFIG

# Load environment variables
load_dotenv()
config = dotenv_values("../../env/.env")

# Configure API key
os.environ["GEMINI_API_KEY"] = config['GOOGLE_API_KEY']

# Define safety settings
safe = [
    {
        "category": "HARM_CATEGORY_HARASSMENT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_HATE_SPEECH",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "threshold": "BLOCK_NONE",
    },
    {
        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
        "threshold": "BLOCK_NONE",
    },
]

class VulnerabilityExtractor:
    def __init__(self, output_dir: str):
        """Initialize the vulnerability extractor"""
        self.output_dir = Path(output_dir)
        self.logger = setup_logging(
            log_dir=LOG_CONFIG["dir"],
            log_level=LOG_CONFIG["level"],
            module_name=__name__
        )
        
        # Initialize Gemini
        genai.configure(api_key=os.environ["GEMINI_API_KEY"])
        
        # Configure generation parameters
        self.generation_config = {
            "temperature": 1,
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 8192,
            "response_mime_type": "text/plain",
        }
        
        # Initialize model with custom prompt template
        self.model = genai.GenerativeModel(
            model_name="gemini-2.0-flash-exp",
            generation_config=self.generation_config,
            system_instruction=self._get_system_prompt(),
            safety_settings=safe
        )

    def _get_system_prompt(self) -> str:
        """Returns the system prompt template for vulnerability extraction"""
        return """Guidelines:
1. First verify if the content relates to the CVE specified based on the official description
2. If the content does not relate to this CVE, respond with "UNRELATED"
3. If no useful vulnerability information is found, respond with "NOINFO" 
4. For relevant content, extract:
   - Root cause of vulnerability
   - Weaknesses/vulnerabilities present
   - Impact of exploitation
   - Attack vectors
   - Required attacker capabilities/position

Additional instructions:
- Preserve original technical details and descriptions
- Remove unrelated content
- Translate non-English content to English
- Note if the content provides more detail than the official CVE description
"""

    def _get_user_prompt(self, cve_id: str, cve_desc: str, content: str) -> str:
        """Formats the user prompt with the specific CVE information and content"""
        return f"""(CVE) ID: {cve_id}
CVE Description: {cve_desc}

===CONTENT to ANALYZE===

{content}"""

    def is_cve_extracted(self, cve_id: str) -> bool:
        """
        Check if vulnerability info has already been extracted by checking for refined.md
        
        Args:
            cve_id: CVE ID to check
            
        Returns:
            bool: True if refined.md exists
        """
        refined_file = self.output_dir / cve_id / "refined" / "refined.md"
        if refined_file.exists():
            self.logger.info(f"Skipping {cve_id} - refined.md already exists")
            return True
        return False
    
    def process_cve(self, cve_id: str) -> bool:
        """
        Process all text files for a CVE and extract vulnerability information
        
        Args:
            cve_id: The CVE ID to process
            
        Returns:
            bool: True if successful extraction
        """
        # Setup directories
        text_dir = self.output_dir / cve_id / "text"
        refined_dir = self.output_dir / cve_id / "refined"
        
        # Consider extracted if refined directory exists and contains files 
        if refined_dir.exists():
            has_refined = any(refined_dir.iterdir())
            if has_refined:
                self.logger.debug(f"{cve_id} already has refined vulnerability content")
                return True
            
        if not text_dir.exists():
            self.logger.warning(f"No text directory found for {cve_id}")
            return False
            
        try:
            # Create refined directory
            refined_dir.mkdir(parents=True, exist_ok=True)
            
            # Combine all text content
            all_content = []
            # Get all files in the text directory
            text_files = list(text_dir.iterdir())
            self.logger.debug(f"Found {len(text_files)} files in {text_dir}")
            
            for text_file in text_files:
                if text_file.is_file():  # Skip directories
                    try:
                        with open(text_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            all_content.append(f"=== Content from {text_file.name} ===\n{content}\n")
                            self.logger.debug(f"Successfully read content from {text_file.name}")
                    except Exception as e:
                        self.logger.error(f"Error reading {text_file}: {e}")
                        continue
            
            if not all_content:
                self.logger.warning(f"No content found for {cve_id}")
                return False
                
            # Save combined raw content
            with open(refined_dir / "combined.md", 'w', encoding='utf-8') as f:
                f.write("\n".join(all_content))
                
            # Extract vulnerability information using LLM
            extracted_info = self._extract_vulnerability_info(
                cve_id=cve_id,
                content="\n".join(all_content)
            )
            
            if extracted_info == "NOINFO":
                self.logger.info(f"No vulnerability information found for {cve_id}")
                return False
                
            # Save extracted information
            with open(refined_dir / "refined.md", 'w', encoding='utf-8') as f:
                f.write(extracted_info)
                
            self.logger.info(f"Successfully processed {cve_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error processing {cve_id}: {e}")
            return False

    def _extract_vulnerability_info(self, cve_id: str, content: str) -> str:
        """
        Extract vulnerability information using LLM
        
        Args:
            cve_id: The CVE ID being processed
            content: The text content to analyze
            
        Returns:
            str: Extracted vulnerability info or "NOINFO"
        """
        try:
            # Get CVE description - in practice you would fetch this from NVD or similar
            # For now using placeholder
            cve_desc = "PLACEHOLDER - Implement CVE description retrieval"
            
            # Format the prompt
            prompt = self._get_user_prompt(cve_id, cve_desc, content)
            
            # Start chat session
            chat = self.model.start_chat()
            
            # Send prompt and get response
            response = chat.send_message(prompt)
            
            if not response.text:
                self.logger.warning(f"Empty response from LLM for {cve_id}")
                return "NOINFO"
                
            # Process response
            result = response.text.strip()
            
            if result in ["UNRELATED", "NOINFO"]:
                return result
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error extracting vulnerability info for {cve_id}: {e}")
            return "NOINFO"