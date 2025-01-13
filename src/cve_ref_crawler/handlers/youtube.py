# src/cve_ref_crawler/handlers/youtube.py

import re
from urllib.parse import urlparse, parse_qs
from typing import Optional
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api.formatters import TextFormatter

def is_youtube_url(url: str) -> bool:
    """Check if URL is from YouTube"""
    parsed = urlparse(url)
    return parsed.netloc in ('www.youtube.com', 'youtube.com', 'youtu.be')

def extract_video_id(url: str) -> Optional[str]:
    """
    Extract video ID from YouTube URL
    
    Handles formats:
    - youtube.com/watch?v=VIDEO_ID
    - youtu.be/VIDEO_ID
    - youtube.com/v/VIDEO_ID
    - youtube.com/embed/VIDEO_ID
    """
    # Handle youtu.be URLs
    if 'youtu.be' in url:
        return url.split('/')[-1].split('?')[0]
        
    # Handle youtube.com URLs
    parsed = urlparse(url)
    if parsed.hostname in ('www.youtube.com', 'youtube.com'):
        if 'watch' in url:
            # Regular watch URL
            query = parse_qs(parsed.query)
            return query.get('v', [None])[0]
        else:
            # Handle /v/ or /embed/ URLs
            path = parsed.path
            if '/v/' in path or '/embed/' in path:
                return path.split('/')[-1]
    
    return None

def get_youtube_transcript(video_id: str) -> Optional[str]:
    """
    Get transcript for YouTube video
    
    Args:
        video_id: YouTube video ID
        
    Returns:
        Formatted transcript text or None if unavailable
    """
    try:
        # Get transcript with timestamps
        transcript = YouTubeTranscriptApi.get_transcript(video_id)
        
        # Format transcript entries
        formatted_entries = []
        for entry in transcript:
            timestamp = f"{int(entry['start'] // 60):02d}:{int(entry['start'] % 60):02d}"
            formatted_entries.append(f"[{timestamp}] {entry['text']}")
            
        return '\n'.join(formatted_entries)
        
    except Exception as e:
        print(f"Error getting YouTube transcript: {e}")
        return None

def handle_youtube_url(url: str) -> Optional[str]:
    """
    Extract transcript from YouTube URL
    
    Args:
        url: YouTube video URL
        
    Returns:
        Transcript text or None if unavailable
    """
    video_id = extract_video_id(url)
    if not video_id:
        return None
        
    return get_youtube_transcript(video_id)