/*
===========================================================================
Copyright (C) 2021 Padworld Entertainment

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
===========================================================================
*/

#include "tr_common.h"

static void* riReAlloc(void *ptr, size_t oldSize, size_t size) {
	void *mem = ri.Malloc(size);
	if (ptr != NULL) {
		Com_Memcpy(mem, ptr, oldSize);
		ri.Free(ptr);
	}
	return mem;
}

static void* riMalloc(size_t size) {
	if (size == 0) {
		return NULL;
	}
	return ri.Malloc(size);
}

static void riFree(void *ptr) {
	if (ptr == NULL) {
		return;
	}
	ri.Free(ptr);
}

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_NO_STDIO
#define STBI_MALLOC riMalloc
#define STBI_FREE riFree
#define STBI_REALLOC_SIZED riReAlloc
#include "stb_image.h"

void R_LoadPNG(const char *name, byte **pic, int *width, int *height) {
	union {
		byte *b;
		void *v;
	} buffer;

	int length;

	*pic = NULL;

	if (width)
		*width = 0;

	if (height)
		*height = 0;

	length = ri.FS_ReadFile((char *)name, &buffer.v);
	if (!buffer.b || length < 0) {
		return;
	}

	int channels_in_file = 0;
	stbi_uc *data = stbi_load_from_memory(buffer.b, length, width, height, &channels_in_file, 4);
	*pic = ri.Malloc(*width * *height * 4);
	Com_Memcpy(*pic, data, *width * *height * 4);
	stbi_image_free(data);

	ri.FS_FreeFile(buffer.v);
}
