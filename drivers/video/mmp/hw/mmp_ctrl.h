/*
 * drivers/video/mmp/hw/mmp_ctrl.h
 *
 *
 * Copyright (C) 2012 Marvell Technology Group Ltd.
 * Authors:  Guoqing Li <ligq@marvell.com>
 *          Lisa Du <cldu@marvell.com>
 *          Zhou Zhu <zzhu3@marvell.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _MMP_CTRL_H_
#define _MMP_CTRL_H_

#include <video/mmp_disp.h>

/* ------------< LCD register >------------ */
struct lcd_regs {
/* TV patch register for MMP2 */
/* 32 bit		TV Video Frame0 Y Starting Address */
#define LCD_TVD_START_ADDR_Y0			(0x0000)
/* 32 bit		TV Video Frame0 U Starting Address */
#define LCD_TVD_START_ADDR_U0			(0x0004)
/* 32 bit		TV Video Frame0 V Starting Address */
#define LCD_TVD_START_ADDR_V0			(0x0008)
/* 32 bit		TV Video Frame0 Command Starting Address */
#define LCD_TVD_START_ADDR_C0			(0x000C)
/* 32 bit		TV Video Frame1 Y Starting Address Register*/
#define LCD_TVD_START_ADDR_Y1			(0x0010)
/* 32 bit		TV Video Frame1 U Starting Address Register*/
#define LCD_TVD_START_ADDR_U1			(0x0014)
/* 32 bit		TV Video Frame1 V Starting Address Register*/
#define LCD_TVD_START_ADDR_V1			(0x0018)
/* 32 bit		TV Video Frame1 Command Starting Address Register*/
#define LCD_TVD_START_ADDR_C1			(0x001C)
/* 32 bit		TV Video Y andC Line Length(Pitch)Register*/
#define LCD_TVD_PITCH_YC			(0x0020)
/* 32 bit		TV Video U andV Line Length(Pitch)Register*/
#define LCD_TVD_PITCH_UV			(0x0024)
/* 32 bit	  TV Video Starting Point on Screen Register*/
#define LCD_TVD_OVSA_HPXL_VLN			(0x0028)
/* 32 bit		TV Video Source Size Register*/
#define LCD_TVD_HPXL_VLN			(0x002C)
/* 32 bit	  TV Video Destination Size (After Zooming)Register*/
#define LCD_TVDZM_HPXL_VLN			(0x0030)
	u32 v_y0;
	u32 v_u0;
	u32 v_v0;
	u32 v_c0;
	u32 v_y1;
	u32 v_u1;
	u32 v_v1;
	u32 v_c1;
	u32 v_pitch_yc;		/* Video Y and C Line Length (Pitch) */
	u32 v_pitch_uv;		/* Video U and V Line Length (Pitch) */
	u32 v_start;		/* Video Starting Point on Screen */
	u32 v_size;			/* Video Source Size */
	u32 v_size_z;		/* Video Destination Size (After Zooming) */

/* 32 bit	   TV Graphic Frame 0 Starting Address Register*/
#define LCD_TVG_START_ADDR0				(0x0034)
/* 32 bit	  TV Graphic Frame 1 Starting Address Register*/
#define LCD_TVG_START_ADDR1				(0x0038)
/* 32 bit		TV Graphic Line Length(Pitch)Register*/
#define LCD_TVG_PITCH					(0x003C)
/* 32 bit		TV Graphic Starting Point on Screen Register*/
#define LCD_TVG_OVSA_HPXL_VLN				(0x0040)
/* 32 bit		TV Graphic Source Size Register*/
#define LCD_TVG_HPXL_VLN				(0x0044)
/* 32 bit		TV Graphic Destination size (after Zooming)Register*/
#define LCD_TVGZM_HPXL_VLN				(0x0048)
	u32 g_0;			/* Graphic Frame 0/1 Starting Address */
	u32 g_1;
	u32 g_pitch;		/* Graphic Line Length (Pitch) */
	u32 g_start;		/* Graphic Starting Point on Screen */
	u32 g_size;			/* Graphic Source Size */
	u32 g_size_z;		/* Graphic Destination Size (After Zooming) */

/* 32 bit	  TV Hardware Cursor Starting Point on screen Register*/
#define LCD_TVC_OVSA_HPXL_VLN				(0x004C)
/* 32 bit		TV Hardware Cursor Size Register */
#define LCD_TVC_HPXL_VLN				(0x0050)
	u32 hc_start;			/* Hardware Cursor */
	u32 hc_size;			/* Hardware Cursor */

/* 32 bit		TV Total Screen Size Register*/
#define LCD_TV_V_H_TOTAL				(0x0054)
/* 32 bit		TV Screen Active Size Register*/
#define LCD_TV_V_H_ACTIVE				(0x0058)
/* 32 bit		TV Screen Horizontal Porch Register*/
#define LCD_TV_H_PORCH					(0x005C)
/* 32 bit		TV Screen Vertical Porch Register*/
#define LCD_TV_V_PORCH					(0x0060)
	u32 screen_size;		/* Screen Total Size */
	u32 screen_active;		/* Screen Active Size */
	u32 screen_h_porch;		/* Screen Horizontal Porch */
	u32 screen_v_porch;		/* Screen Vertical Porch */

/* 32 bit		TV Screen Blank Color Register*/
#define LCD_TV_BLANKCOLOR				(0x0064)
/* 32 bit		TV Hardware Cursor Color1 Register*/
#define LCD_TV_ALPHA_COLOR1				(0x0068)
/* 32 bit		TV Hardware Cursor Color2 Register*/
#define LCD_TV_ALPHA_COLOR2				(0x006C)
	u32 blank_color;		/* Screen Blank Color */
	u32 hc_Alpha_color1;	/* Hardware Cursor Color1 */
	u32 hc_Alpha_color2;	/* Hardware Cursor Color2 */

/* 32 bit		TV Video Y Color Key Control*/
#define LCD_TV_COLORKEY_Y				(0x0070)
/* 32 bit		TV Video U Color Key Control*/
#define LCD_TV_COLORKEY_U				(0x0074)
/* 32 bit		TV Video V Color Key Control*/
#define LCD_TV_COLORKEY_V				(0x0078)
	u32 v_colorkey_y;		/* Video Y Color Key Control */
	u32 v_colorkey_u;		/* Video U Color Key Control */
	u32 v_colorkey_v;		/* Video V Color Key Control */

/* 32 bit		TV VSYNC PulsePixel Edge Control Register*/
#define LCD_TV_SEPXLCNT					(0x007C)
	u32 vsync_ctrl;			/* VSYNC PulsePixel Edge Control */
};

#define intf_ctrl(id)		((id) ? (((id) & 1) ? LCD_TVIF_CTRL : \
				LCD_DUMB2_CTRL) : LCD_SPU_DUMB_CTRL)
#define dma_ctrl0(id)	   ((id) ? (((id) & 1) ? LCD_TV_CTRL0 : \
				LCD_PN2_CTRL0) : LCD_SPU_DMA_CTRL0)
#define dma_ctrl1(id)	   ((id) ? (((id) & 1) ? LCD_TV_CTRL1 : \
				LCD_PN2_CTRL1) : LCD_SPU_DMA_CTRL1)
#define dma_ctrl(ctrl1, id)	 (ctrl1 ? dma_ctrl1(id) : dma_ctrl0(id))

/* 32 bit		TV Path DMA Control 0*/
#define LCD_TV_CTRL0					(0x0080)
/* 32 bit		TV Path DMA Control 1*/
#define LCD_TV_CTRL1					(0x0084)
/* 32 bit		TV Path Video Contrast*/
#define LCD_TV_CONTRAST					(0x0088)
/* 32 bit		TV Path Video Saturation*/
#define LCD_TV_SATURATION				(0x008C)
/* 32 bit		TV Path Video Hue Adjust*/
#define LCD_TV_CBSH_HUE					(0x0090)
/* 32 bit TV Path TVIF Control	Register */
#define LCD_TVIF_CTRL					(0x0094)
#define TV_VBLNK_VALID_EN				(1 << 12)

/* 32 bit TV Path I/O Pad Control*/
#define LCD_TVIOPAD_CTRL				(0x0098)
/* 32 bit TV Path Cloc	Divider  */
#define LCD_TCLK_DIV					(0x009C)

#define LCD_SCLK(path) ((PATH_PN == path->id) ? LCD_CFG_SCLK_DIV :\
	((PATH_TV == path->id) ? LCD_TCLK_DIV : LCD_PN2_SCLK_DIV))

/* dither configure */
#ifdef CONFIG_CPU_PXA988
#define LCD_DITHER_CTRL				(0x01EC)
#else
#define LCD_DITHER_CTRL				(0x00A0)
#endif

#define DITHER_TBL_INDEX_SEL(s)		((s) << 16)
#define DITHER_MODE2(m)				((m) << 12)
#define DITHER_MODE2_SHIFT			(12)
#define DITHER_4X8_EN2				(1 << 9)
#define DITHER_4X8_EN2_SHIFT		(9)
#define DITHER_EN2					(1 << 8)
#define DITHER_MODE1(m)				((m) << 4)
#define DITHER_MODE1_SHIFT			(4)
#define DITHER_4X8_EN1				(1 << 1)
#define DITHER_4X8_EN1_SHIFT		(1)
#define DITHER_EN1					(1)

/* dither table data was fixed by video bpp of input and output*/
#ifdef CONFIG_CPU_PXA988
#define DITHER_TB_4X4_INDEX0		(0x6e4ca280)
#define DITHER_TB_4X4_INDEX1		(0x5d7f91b3)
#define DITHER_TB_4X8_INDEX0		(0xb391a280)
#define DITHER_TB_4X8_INDEX1		(0x7f5d6e4c)
#define DITHER_TB_4X8_INDEX2		(0x80a291b3)
#define DITHER_TB_4X8_INDEX3		(0x4c6e5d7f)
#define LCD_DITHER_TBL_DATA		(0x01F0)
#else
#define DITHER_TB_4X4_INDEX0		(0x3b19f7d5)
#define DITHER_TB_4X4_INDEX1		(0x082ac4e6)
#define DITHER_TB_4X8_INDEX0		(0xf7d508e6)
#define DITHER_TB_4X8_INDEX1		(0x3b194c2a)
#define DITHER_TB_4X8_INDEX2		(0xc4e6d5f7)
#define DITHER_TB_4X8_INDEX3		(0x082a193b)
#define LCD_DITHER_TBL_DATA		(0x00A4)
#endif

/* Video Frame 0&1 start address registers */
#define	LCD_SPU_DMA_START_ADDR_Y0	0x00C0
#define	LCD_SPU_DMA_START_ADDR_U0	0x00C4
#define	LCD_SPU_DMA_START_ADDR_V0	0x00C8
#define LCD_CFG_DMA_START_ADDR_0	0x00CC /* Cmd address */
#define	LCD_SPU_DMA_START_ADDR_Y1	0x00D0
#define	LCD_SPU_DMA_START_ADDR_U1	0x00D4
#define	LCD_SPU_DMA_START_ADDR_V1	0x00D8
#define LCD_CFG_DMA_START_ADDR_1	0x00DC /* Cmd address */

/* YC & UV Pitch */
#define LCD_SPU_DMA_PITCH_YC		0x00E0
#define	 SPU_DMA_PITCH_C(c)		((c)<<16)
#define	 SPU_DMA_PITCH_Y(y)		(y)
#define LCD_SPU_DMA_PITCH_UV		0x00E4
#define	 SPU_DMA_PITCH_V(v)		((v)<<16)
#define	 SPU_DMA_PITCH_U(u)		(u)

/* Video Starting Point on Screen Register */
#define LCD_SPUT_DMA_OVSA_HPXL_VLN		0x00E8
#define	 CFG_DMA_OVSA_VLN(y)			((y)<<16) /* 0~0xfff */
#define	 CFG_DMA_OVSA_HPXL(x)			(x)	 /* 0~0xfff */

/* Video Size Register */
#define LCD_SPU_DMA_HPXL_VLN			0x00EC
#define	 CFG_DMA_VLN(y)				((y)<<16)
#define	 CFG_DMA_HPXL(x)			(x)

/* Video Size After zooming Register */
#define LCD_SPU_DZM_HPXL_VLN			0x00F0
#define	 CFG_DZM_VLN(y)				((y)<<16)
#define	 CFG_DZM_HPXL(x)			(x)

/* Graphic Frame 0&1 Starting Address Register */
#define LCD_CFG_GRA_START_ADDR0			0x00F4
#define LCD_CFG_GRA_START_ADDR1			0x00F8

/* Graphic Frame Pitch */
#define LCD_CFG_GRA_PITCH			0x00FC

/* Graphic Starting Point on Screen Register */
#define LCD_SPU_GRA_OVSA_HPXL_VLN		0x0100
#define	 CFG_GRA_OVSA_VLN(y)			((y)<<16)
#define	 CFG_GRA_OVSA_HPXL(x)			(x)

/* Graphic Size Register */
#define LCD_SPU_GRA_HPXL_VLN			0x0104
#define	 CFG_GRA_VLN(y)				((y)<<16)
#define	 CFG_GRA_HPXL(x)			(x)

/* Graphic Size after Zooming Register */
#define LCD_SPU_GZM_HPXL_VLN			0x0108
#define	 CFG_GZM_VLN(y)				((y)<<16)
#define	 CFG_GZM_HPXL(x)			(x)

/* HW Cursor Starting Point on Screen Register */
#define LCD_SPU_HWC_OVSA_HPXL_VLN		0x010C
#define	 CFG_HWC_OVSA_VLN(y)			((y)<<16)
#define	 CFG_HWC_OVSA_HPXL(x)			(x)

/* HW Cursor Size */
#define LCD_SPU_HWC_HPXL_VLN			0x0110
#define	 CFG_HWC_VLN(y)				((y)<<16)
#define	 CFG_HWC_HPXL(x)			(x)

/* Total Screen Size Register */
#define LCD_SPUT_V_H_TOTAL			0x0114
#define	 CFG_V_TOTAL(y)				((y)<<16)
#define	 CFG_H_TOTAL(x)				(x)

/* Total Screen Active Size Register */
#define LCD_SPU_V_H_ACTIVE			0x0118
#define	 CFG_V_ACTIVE(y)			((y)<<16)
#define	 CFG_H_ACTIVE(x)			(x)

/* Screen H&V Porch Register */
#define LCD_SPU_H_PORCH				0x011C
#define	 CFG_H_BACK_PORCH(b)			((b)<<16)
#define	 CFG_H_FRONT_PORCH(f)			(f)
#define LCD_SPU_V_PORCH				0x0120
#define	 CFG_V_BACK_PORCH(b)			((b)<<16)
#define	 CFG_V_FRONT_PORCH(f)			(f)

/* Screen Blank Color Register */
#define LCD_SPU_BLANKCOLOR			0x0124
#define  CFG_BLANKCOLOR_MASK			0x00FFFFFF
#define  CFG_BLANKCOLOR_R_MASK			0x000000FF
#define  CFG_BLANKCOLOR_G_MASK			0x0000FF00
#define  CFG_BLANKCOLOR_B_MASK			0x00FF0000

/* HW Cursor Color 1&2 Register */
#define LCD_SPU_ALPHA_COLOR1			0x0128
#define	 CFG_HWC_COLOR1				0x00FFFFFF
#define	 CFG_HWC_COLOR1_R(red)			((red)<<16)
#define	 CFG_HWC_COLOR1_G(green)		((green)<<8)
#define	 CFG_HWC_COLOR1_B(blue)			(blue)
#define	 CFG_HWC_COLOR1_R_MASK			0x000000FF
#define	 CFG_HWC_COLOR1_G_MASK			0x0000FF00
#define	 CFG_HWC_COLOR1_B_MASK			0x00FF0000
#define LCD_SPU_ALPHA_COLOR2			0x012C
#define	 CFG_HWC_COLOR2				0x00FFFFFF
#define	 CFG_HWC_COLOR2_R_MASK			0x000000FF
#define	 CFG_HWC_COLOR2_G_MASK			0x0000FF00
#define	 CFG_HWC_COLOR2_B_MASK			0x00FF0000

/* Video YUV Color Key Control */
#define LCD_SPU_COLORKEY_Y			0x0130
#define	 CFG_CKEY_Y2(y2)			((y2)<<24)
#define	 CFG_CKEY_Y2_MASK			0xFF000000
#define	 CFG_CKEY_Y1(y1)			((y1)<<16)
#define	 CFG_CKEY_Y1_MASK			0x00FF0000
#define	 CFG_CKEY_Y(y)				((y)<<8)
#define	 CFG_CKEY_Y_MASK			0x0000FF00
#define	 CFG_ALPHA_Y(y)				(y)
#define	 CFG_ALPHA_Y_MASK			0x000000FF
#define LCD_SPU_COLORKEY_U			0x0134
#define	 CFG_CKEY_U2(u2)			((u2)<<24)
#define	 CFG_CKEY_U2_MASK			0xFF000000
#define	 CFG_CKEY_U1(u1)			((u1)<<16)
#define	 CFG_CKEY_U1_MASK			0x00FF0000
#define	 CFG_CKEY_U(u)				((u)<<8)
#define	 CFG_CKEY_U_MASK			0x0000FF00
#define	 CFG_ALPHA_U(u)				(u)
#define	 CFG_ALPHA_U_MASK			0x000000FF
#define LCD_SPU_COLORKEY_V			0x0138
#define	 CFG_CKEY_V2(v2)			((v2)<<24)
#define	 CFG_CKEY_V2_MASK			0xFF000000
#define	 CFG_CKEY_V1(v1)			((v1)<<16)
#define	 CFG_CKEY_V1_MASK			0x00FF0000
#define	 CFG_CKEY_V(v)				((v)<<8)
#define	 CFG_CKEY_V_MASK			0x0000FF00
#define	 CFG_ALPHA_V(v)				(v)
#define	 CFG_ALPHA_V_MASK			0x000000FF

/* Graphics/Video DMA color key enable bits in LCD_TV_CTRL1 */
#define	 CFG_CKEY_GRA				0x2
#define	 CFG_CKEY_DMA				0x1

/* Interlace mode enable bits in LCD_TV_CTRL1 */
#define     CFG_TV_INTERLACE_EN                 (1 << 22)
#define     CFG_TV_NIB                          (1 << 0)

#define LCD_PN_SEPXLCNT				0x013c /* MMP2 */

/* SPI Read Data Register */
#define LCD_SPU_SPI_RXDATA			0x0140

/* Smart Panel Read Data Register */
#define LCD_SPU_ISA_RSDATA			0x0144
#define	 ISA_RXDATA_16BIT_1_DATA_MASK		0x000000FF
#define	 ISA_RXDATA_16BIT_2_DATA_MASK		0x0000FF00
#define	 ISA_RXDATA_16BIT_3_DATA_MASK		0x00FF0000
#define	 ISA_RXDATA_16BIT_4_DATA_MASK		0xFF000000
#define	 ISA_RXDATA_32BIT_1_DATA_MASK		0x00FFFFFF

#define LCD_SPU_DBG_ISA				(0x0148) /* TTC */
#define LCD_SPU_DMAVLD_YC			(0x014C)
#define LCD_SPU_DMAVLD_UV			(0x0150)
#define LCD_SPU_DMAVLD_UVSPU_GRAVLD		(0x0154)

#define LCD_READ_IOPAD				(0x0148) /* MMP2*/
#define LCD_DMAVLD_YC				(0x014C)
#define LCD_DMAVLD_UV				(0x0150)
#define LCD_TVGGRAVLD_HLEN			(0x0154)

/* HWC SRAM Read Data Register */
#define LCD_SPU_HWC_RDDAT			0x0158

/* Gamma Table SRAM Read Data Register */
#define LCD_SPU_GAMMA_RDDAT			0x015c
#define	 CFG_GAMMA_RDDAT_MASK			0x000000FF

/* Palette Table SRAM Read Data Register */
#define LCD_SPU_PALETTE_RDDAT			0x0160
#define	 CFG_PALETTE_RDDAT_MASK			0x00FFFFFF

#define LCD_SPU_DBG_DMATOP			(0x0164) /* TTC */
#define LCD_SPU_DBG_GRATOP			(0x0168)
#define LCD_SPU_DBG_TXCTRL			(0x016C)
#define LCD_SPU_DBG_SLVTOP			(0x0170)
#define LCD_SPU_DBG_MUXTOP			(0x0174)

#define LCD_SLV_DBG				(0x0164) /* MMP2 */
#define LCD_TVDVLD_YC				(0x0168)
#define LCD_TVDVLD_UV				(0x016C)
#define LCD_TVC_RDDAT				(0x0170)
#define LCD_TV_GAMMA_RDDAT			(0x0174)

/* I/O Pads Input Read Only Register */
#define LCD_SPU_IOPAD_IN			0x0178
#define	 CFG_IOPAD_IN_MASK			0x0FFFFFFF

#define LCD_TV_PALETTE_RDDAT			(0x0178) /* MMP2 */

/* Reserved Read Only Registers */
#define LCD_CFG_RDREG5F				0x017C
#define	 IRE_FRAME_CNT_MASK			0x000000C0
#define	 IPE_FRAME_CNT_MASK			0x00000030
#define	 GRA_FRAME_CNT_MASK			0x0000000C /* Graphic */
#define	 DMA_FRAME_CNT_MASK			0x00000003 /* Video */

#define LCD_FRAME_CNT				(0x017C) /* MMP2 */

/* SPI Control Register. */
#define LCD_SPU_SPI_CTRL			0x0180
#define	 CFG_SCLKCNT(div)			((div)<<24) /* 0xFF~0x2 */
#define	 CFG_SCLKCNT_MASK			0xFF000000
#define	 CFG_RXBITS(rx)				(((rx) - 1)<<16) /* 0x1F~0x1 */
#define	 CFG_RXBITS_MASK			0x00FF0000
#define	 CFG_TXBITS(tx)				(((tx) - 1)<<8) /* 0x1F~0x1 */
#define	 CFG_TXBITS_MASK			0x0000FF00
#define	 CFG_CLKINV(clk)			((clk)<<7)
#define	 CFG_CLKINV_MASK			0x00000080
#define	 CFG_KEEPXFER(transfer)			((transfer)<<6)
#define	 CFG_KEEPXFER_MASK			0x00000040
#define	 CFG_RXBITSTO0(rx)			((rx)<<5)
#define	 CFG_RXBITSTO0_MASK			0x00000020
#define	 CFG_TXBITSTO0(tx)			((tx)<<4)
#define	 CFG_TXBITSTO0_MASK			0x00000010
#define	 CFG_SPI_ENA(spi)			((spi)<<3)
#define	 CFG_SPI_ENA_MASK			0x00000008
#define	 CFG_SPI_SEL(spi)			((spi)<<2)
#define	 CFG_SPI_SEL_MASK			0x00000004
#define	 CFG_SPI_3W4WB(wire)			((wire)<<1)
#define	 CFG_SPI_3W4WB_MASK			0x00000002
#define	 CFG_SPI_START(start)			(start)
#define	 CFG_SPI_START_MASK			0x00000001

/* SPI Tx Data Register */
#define LCD_SPU_SPI_TXDATA			0x0184

/*
   1. Smart Pannel 8-bit Bus Control Register.
   2. AHB Slave Path Data Port Register
*/
#define LCD_SPU_SMPN_CTRL			0x0188

/* DMA Control 0 Register */
#define LCD_SPU_DMA_CTRL0			0x0190
#define	 CFG_NOBLENDING(nb)			((nb)<<31)
#define	 CFG_NOBLENDING_MASK			0x80000000
#define	 CFG_GAMMA_ENA(gn)			((gn)<<30)
#define	 CFG_GAMMA_ENA_MASK			0x40000000
#define	 CFG_CBSH_ENA(cn)			((cn)<<29)
#define	 CFG_CBSH_ENA_MASK			0x20000000
#define	 CFG_PALETTE_ENA(pn)			((pn)<<28)
#define	 CFG_PALETTE_ENA_MASK			0x10000000
#define	 CFG_ARBFAST_ENA(an)			((an)<<27)
#define	 CFG_ARBFAST_ENA_MASK			0x08000000
#define	 CFG_HWC_1BITMOD(mode)			((mode)<<26)
#define	 CFG_HWC_1BITMOD_MASK			0x04000000
#define	 CFG_HWC_1BITENA(mn)			((mn)<<25)
#define	 CFG_HWC_1BITENA_MASK			0x02000000
#define	 CFG_HWC_ENA(cn)			((cn)<<24)
#define	 CFG_HWC_ENA_MASK			0x01000000
#define	 CFG_DMAFORMAT(dmaformat)		((dmaformat)<<20)
#define	 CFG_DMAFORMAT_MASK			0x00F00000
#define	 CFG_GRAFORMAT(graformat)		((graformat)<<16)
#define	 CFG_GRAFORMAT_MASK			0x000F0000
/* for graphic part */
#define	 CFG_GRA_FTOGGLE(toggle)		((toggle)<<15)
#define	 CFG_GRA_FTOGGLE_MASK			0x00008000
#define	 CFG_GRA_HSMOOTH(smooth)		((smooth)<<14)
#define	 CFG_GRA_HSMOOTH_MASK			0x00004000
#define	 CFG_GRA_TSTMODE(test)			((test)<<13)
#define	 CFG_GRA_TSTMODE_MASK			0x00002000
#define	 CFG_GRA_SWAPRB(swap)			((swap)<<12)
#define	 CFG_GRA_SWAPRB_MASK			0x00001000
#define	 CFG_GRA_SWAPUV(swap)			((swap)<<11)
#define	 CFG_GRA_SWAPUV_MASK			0x00000800
#define	 CFG_GRA_SWAPYU(swap)			((swap)<<10)
#define	 CFG_GRA_SWAPYU_MASK			0x00000400
#define	 CFG_GRA_SWAP_MASK			0x00001C00
#define	 CFG_YUV2RGB_GRA(cvrt)			((cvrt)<<9)
#define	 CFG_YUV2RGB_GRA_MASK			0x00000200
#define	 CFG_GRA_ENA(gra)			((gra)<<8)
#define	 CFG_GRA_ENA_MASK			0x00000100
#define dma0_gfx_masks	(CFG_GRAFORMAT_MASK | CFG_GRA_FTOGGLE_MASK | \
	CFG_GRA_HSMOOTH_MASK | CFG_GRA_TSTMODE_MASK | CFG_GRA_SWAP_MASK | \
	CFG_YUV2RGB_GRA_MASK | CFG_GRA_ENA_MASK)
/* for video part */
#define	 CFG_DMA_FTOGGLE(toggle)		((toggle)<<7)
#define	 CFG_DMA_FTOGGLE_MASK			0x00000080
#define	 CFG_DMA_HSMOOTH(smooth)		((smooth)<<6)
#define	 CFG_DMA_HSMOOTH_MASK			0x00000040
#define	 CFG_DMA_TSTMODE(test)			((test)<<5)
#define	 CFG_DMA_TSTMODE_MASK			0x00000020
#define	 CFG_DMA_SWAPRB(swap)			((swap)<<4)
#define	 CFG_DMA_SWAPRB_MASK			0x00000010
#define	 CFG_DMA_SWAPUV(swap)			((swap)<<3)
#define	 CFG_DMA_SWAPUV_MASK			0x00000008
#define	 CFG_DMA_SWAPYU(swap)			((swap)<<2)
#define	 CFG_DMA_SWAPYU_MASK			0x00000004
#define	 CFG_DMA_SWAP_MASK			0x0000001C
#define	 CFG_YUV2RGB_DMA(cvrt)			((cvrt)<<1)
#define	 CFG_YUV2RGB_DMA_MASK			0x00000002
#define	 CFG_DMA_ENA(video)			(video)
#define	 CFG_DMA_ENA_MASK			0x00000001
#define dma0_vid_masks	(CFG_DMAFORMAT_MASK | CFG_DMA_FTOGGLE_MASK | \
	CFG_DMA_HSMOOTH_MASK | CFG_DMA_TSTMODE_MASK | CFG_DMA_SWAP_MASK | \
	CFG_YUV2RGB_DMA_MASK | CFG_DMA_ENA_MASK)
#define dma_palette(val)		((val ? 1 : 0) << 28)
#define dma_fmt(vid, val)		((val & 0xf) << ((vid) ? 20 : 16))
#define dma_swaprb(vid, val)		((val ? 1 : 0) << ((vid) ? 4 : 12))
#define dma_swapuv(vid, val)		((val ? 1 : 0) << ((vid) ? 3 : 11))
#define dma_swapyuv(vid, val)		((val ? 1 : 0) << ((vid) ? 2 : 10))
#define dma_csc(vid, val)		((val ? 1 : 0) << ((vid) ? 1 : 9))
#define dma_hsmooth(vid, val)		((val ? 1 : 0) << ((vid) ? 6 : 14))
#define dma_mask(vid)	(dma_palette(1) | dma_fmt(vid, 0xf) | dma_csc(vid, 1) \
	| dma_swaprb(vid, 1) | dma_swapuv(vid, 1) | dma_swapyuv(vid, 1))

/* DMA Control 1 Register */
#define LCD_SPU_DMA_CTRL1			0x0194
#define	 CFG_FRAME_TRIG(trig)			((trig)<<31)
#define	 CFG_FRAME_TRIG_MASK			0x80000000
#define	 CFG_VSYNC_TRIG(trig)			((trig)<<28)
#define	 CFG_VSYNC_TRIG_MASK			0x70000000
#define	 CFG_VSYNC_INV(inv)			((inv)<<27)
#define	 CFG_VSYNC_INV_MASK			0x08000000
#define	 CFG_COLOR_KEY_MODE(cmode)		((cmode)<<24)
#define	 CFG_COLOR_KEY_MASK			0x07000000
#define	 CFG_CARRY(carry)			((carry)<<23)
#define	 CFG_CARRY_MASK				0x00800000
#define	 CFG_LNBUF_ENA(lnbuf)			((lnbuf)<<22)
#define	 CFG_LNBUF_ENA_MASK			0x00400000
#define	 CFG_GATED_ENA(gated)			((gated)<<21)
#define	 CFG_GATED_ENA_MASK			0x00200000
#define	 CFG_PWRDN_ENA(power)			((power)<<20)
#define	 CFG_PWRDN_ENA_MASK			0x00100000
#define	 CFG_DSCALE(dscale)			((dscale)<<18)
#define	 CFG_DSCALE_MASK			0x000C0000
#define	 CFG_ALPHA_MODE(amode)			((amode)<<16)
#define	 CFG_ALPHA_MODE_MASK			0x00030000
#define	 CFG_ALPHA(alpha)			((alpha)<<8)
#define	 CFG_ALPHA_MASK				0x0000FF00
#define	 CFG_PXLCMD(pxlcmd)			(pxlcmd)
#define	 CFG_PXLCMD_MASK			0x000000FF

/* SRAM Control Register */
#define LCD_SPU_SRAM_CTRL			0x0198
#define	 CFG_SRAM_INIT_WR_RD(mode)		((mode)<<14)
#define	 CFG_SRAM_INIT_WR_RD_MASK		0x0000C000
#define	 CFG_SRAM_ADDR_LCDID(id)		((id)<<8)
#define	 CFG_SRAM_ADDR_LCDID_MASK		0x00000F00
#define	 CFG_SRAM_ADDR(addr)			(addr)
#define	 CFG_SRAM_ADDR_MASK			0x000000FF

/* SRAM Write Data Register */
#define LCD_SPU_SRAM_WRDAT			0x019C

/* SRAM RTC/WTC Control Register */
#define LCD_SPU_SRAM_PARA0			0x01A0

/* SRAM Power Down Control Register */
#define LCD_SPU_SRAM_PARA1			0x01A4
#define	 CFG_CSB_256x32(hwc)			((hwc)<<15)	/* HWC */
#define	 CFG_CSB_256x32_MASK			0x00008000
#define	 CFG_CSB_256x24(palette)		((palette)<<14)	/* Palette */
#define	 CFG_CSB_256x24_MASK			0x00004000
#define	 CFG_CSB_256x8(gamma)			((gamma)<<13)	/* Gamma */
#define	 CFG_CSB_256x8_MASK			0x00002000
#define	 CFG_PDWN256x32(pdwn)			((pdwn)<<7)	/* HWC */
#define	 CFG_PDWN256x32_MASK			0x00000080
#define	 CFG_PDWN256x24(pdwn)			((pdwn)<<6)	/* Palette */
#define	 CFG_PDWN256x24_MASK			0x00000040
#define	 CFG_PDWN256x8(pdwn)			((pdwn)<<5)	/* Gamma */
#define	 CFG_PDWN256x8_MASK			0x00000020
#define	 CFG_PDWN32x32(pdwn)			((pdwn)<<3)
#define	 CFG_PDWN32x32_MASK			0x00000008
#define	 CFG_PDWN16x66(pdwn)			((pdwn)<<2)
#define	 CFG_PDWN16x66_MASK			0x00000004
#define	 CFG_PDWN32x66(pdwn)			((pdwn)<<1)
#define	 CFG_PDWN32x66_MASK			0x00000002
#define	 CFG_PDWN64x66(pdwn)			(pdwn)
#define	 CFG_PDWN64x66_MASK			0x00000001

/* Smart or Dumb Panel Clock Divider */
#define LCD_CFG_SCLK_DIV			0x01A8
#define	 SCLK_SRC_SEL(src)		((src)<<31)
#define	 SCLK_SRC_SEL_MASK		0x80000000
#define  SCLK_DISABLE				(1<<28)
#define	 CLK_FRACDIV(frac)			((frac)<<16)
#define	 CLK_FRACDIV_MASK			0x0FFF0000
#define	 DSI1_BITCLK_DIV(div)			(div<<8)
#define	 DSI1_BITCLK_DIV_MASK			0x00000F00
#define	 CLK_INT_DIV(div)			(div)
#define	 CLK_INT_DIV_MASK			0x000000FF

/* Video Contrast Register */
#define LCD_SPU_CONTRAST			0x01AC
#define	 CFG_BRIGHTNESS(bright)			((bright)<<16)
#define	 CFG_BRIGHTNESS_MASK			0xFFFF0000
#define	 CFG_CONTRAST(contrast)			(contrast)
#define	 CFG_CONTRAST_MASK			0x0000FFFF

/* Video Saturation Register */
#define LCD_SPU_SATURATION			0x01B0
#define	 CFG_C_MULTS(mult)			((mult)<<16)
#define	 CFG_C_MULTS_MASK			0xFFFF0000
#define	 CFG_SATURATION(sat)			(sat)
#define	 CFG_SATURATION_MASK			0x0000FFFF

/* Video Hue Adjust Register */
#define LCD_SPU_CBSH_HUE			0x01B4
#define	 CFG_SIN0(sin0)				((sin0)<<16)
#define	 CFG_SIN0_MASK				0xFFFF0000
#define	 CFG_COS0(con0)				(con0)
#define	 CFG_COS0_MASK				0x0000FFFF

/* Dump LCD Panel Control Register */
#define LCD_SPU_DUMB_CTRL			0x01B8
#define	 CFG_DUMBMODE(mode)			((mode)<<28)
#define	 CFG_DUMBMODE_MASK			0xF0000000
#define	 CFG_LCDGPIO_O(data)			((data)<<20)
#define	 CFG_LCDGPIO_O_MASK			0x0FF00000
#define	 CFG_LCDGPIO_ENA(gpio)			((gpio)<<12)
#define	 CFG_LCDGPIO_ENA_MASK			0x000FF000
#define	 CFG_BIAS_OUT(bias)			((bias)<<8)
#define	 CFG_BIAS_OUT_MASK			0x00000100
#define	 CFG_REVERSE_RGB(RGB)			((RGB)<<7)
#define	 CFG_REVERSE_RGB_MASK			0x00000080
#define	 CFG_INV_COMPBLANK(blank)		((blank)<<6)
#define	 CFG_INV_COMPBLANK_MASK			0x00000040
#define	 CFG_INV_COMPSYNC(sync)			((sync)<<5)
#define	 CFG_INV_COMPSYNC_MASK			0x00000020
#define	 CFG_INV_HENA(hena)			((hena)<<4)
#define	 CFG_INV_HENA_MASK			0x00000010
#define	 CFG_INV_VSYNC(vsync)			((vsync)<<3)
#define	 CFG_INV_VSYNC_MASK			0x00000008
#define	 CFG_INV_HSYNC(hsync)			((hsync)<<2)
#define	 CFG_INV_HSYNC_MASK			0x00000004
#define	 CFG_INV_PCLK(pclk)			((pclk)<<1)
#define	 CFG_INV_PCLK_MASK			0x00000002
#define	 CFG_DUMB_ENA(dumb)			(dumb)
#define	 CFG_DUMB_ENA_MASK			0x00000001

/* LCD I/O Pads Control Register */
#define SPU_IOPAD_CONTROL			0x01BC
#define	 CFG_GRA_VM_ENA(vm)			((vm)<<15)
#define	 CFG_GRA_VM_ENA_MASK			0x00008000
#define	 CFG_DMA_VM_ENA(vm)			((vm)<<13)
#define	 CFG_DMA_VM_ENA_MASK			0x00002000
#define	 CFG_CMD_VM_ENA(vm)			((vm)<<12)
#define	 CFG_CMD_VM_ENA_MASK			0x00001000
#define	 CFG_CSC(csc)				((csc)<<8)
#define	 CFG_CSC_MASK				0x00000300
#define	 CFG_BOUNDARY(size)			((size)<<5)
#define	 CFG_BOUNDARY_MASK			0x00000020
#define	 CFG_BURST(len)				((len)<<4)
#define	 CFG_BURST_MASK				0x00000010
#define	 CFG_IOPADMODE(iopad)			(iopad)
#define	 CFG_IOPADMODE_MASK			0x0000000F

/* LCD Interrupt Control Register */
#define SPU_IRQ_ENA				0x01C0
#define	 DMA_FRAME_IRQ0_ENA(irq)		((irq)<<31)
#define	 DMA_FRAME_IRQ0_ENA_MASK		0x80000000
#define	 DMA_FRAME_IRQ1_ENA(irq)		((irq)<<30)
#define	 DMA_FRAME_IRQ1_ENA_MASK		0x40000000
#define	 DMA_FF_UNDERFLOW_ENA(ff)		((ff)<<29)
#define	 DMA_FF_UNDERFLOW_ENA_MASK		0x20000000
#define	 AXI_BUS_ERROR_IRQ_ENA(irq)		((irq)<<28)
#define	 AXI_BUS_ERROR_IRQ_ENA_MASK		0x10000000
#define	 GRA_FRAME_IRQ0_ENA(irq)		((irq)<<27)
#define	 GRA_FRAME_IRQ0_ENA_MASK		0x08000000
#define	 GRA_FRAME_IRQ1_ENA(irq)		((irq)<<26)
#define	 GRA_FRAME_IRQ1_ENA_MASK		0x04000000
#define	 GRA_FF_UNDERFLOW_ENA(ff)		((ff)<<25)
#define	 GRA_FF_UNDERFLOW_ENA_MASK		0x02000000
#define	 VSYNC_IRQ_ENA(vsync_irq)		((vsync_irq)<<23)
#define	 VSYNC_IRQ_ENA_MASK			0x00800000
#define	 DUMB_FRAMEDONE_ENA(fdone)		((fdone)<<22)
#define	 DUMB_FRAMEDONE_ENA_MASK		0x00400000
#define	 TWC_FRAMEDONE_ENA(fdone)		((fdone)<<21)
#define	 TWC_FRAMEDONE_ENA_MASK			0x00200000
#define	 HWC_FRAMEDONE_ENA(fdone)		((fdone)<<20)
#define	 HWC_FRAMEDONE_ENA_MASK			0x00100000
#define	 SLV_IRQ_ENA(irq)			((irq)<<19)
#define	 SLV_IRQ_ENA_MASK			0x00080000
#define	 SPI_IRQ_ENA(irq)			((irq)<<18)
#define	 SPI_IRQ_ENA_MASK			0x00040000
#define	 PWRDN_IRQ_ENA(irq)			((irq)<<17)
#define	 PWRDN_IRQ_ENA_MASK			0x00020000
#define	 AXI_LATENCY_TOO_LONG_IRQ_ENA(irq)	((irq)<<16)
#define  AXI_LATENCY_TOO_LONG_IRQ_ENA_MASK	0x00010000
#define	 CLEAN_SPU_IRQ_ISR(irq)			(irq)
#define	 CLEAN_SPU_IRQ_ISR_MASK			0x0000FFFF
#define	 TV_DMA_FRAME_IRQ0_ENA(irq)		((irq)<<15)
#define	 TV_DMA_FRAME_IRQ0_ENA_MASK		0x00008000
#define	 TV_DMA_FRAME_IRQ1_ENA(irq)		((irq)<<14)
#define	 TV_DMA_FRAME_IRQ1_ENA_MASK		0x00004000
#define	 TV_DMA_FF_UNDERFLOW_ENA(unerrun)	((unerrun)<<13)
#define	 TV_DMA_FF_UNDERFLOW_ENA_MASK		0x00002000
#define	 TVSYNC_IRQ_ENA(irq)			((irq)<<12)
#define	 TVSYNC_IRQ_ENA_MASK			0x00001000
#define	 TV_FRAME_IRQ0_ENA(irq)			((irq)<<11)
#define	 TV_FRAME_IRQ0_ENA_MASK			0x00000800
#define	 TV_FRAME_IRQ1_ENA(irq)			((irq)<<10)
#define	 TV_FRAME_IRQ1_ENA_MASK			0x00000400
#define	 TV_GRA_FF_UNDERFLOW_ENA(unerrun)	((unerrun)<<9)
#define	 TV_GRA_FF_UNDERFLOW_ENA_MASK		0x00000200
#define	 TV_FRAMEDONE_ENA(irq)			((irq)<<8)
#define	 TV_FRAMEDONE_ENA_MASK			0x00000100

/* FIXME - JUST GUESS */
#define	 PN2_DMA_FRAME_IRQ0_ENA(irq)		((irq)<<7)
#define	 PN2_DMA_FRAME_IRQ0_ENA_MASK		0x00000080
#define	 PN2_DMA_FRAME_IRQ1_ENA(irq)		((irq)<<6)
#define	 PN2_DMA_FRAME_IRQ1_ENA_MASK		0x00000040
#define	 PN2_DMA_FF_UNDERFLOW_ENA(ff)		((ff)<<5)
#define	 PN2_DMA_FF_UNDERFLOW_ENA_MASK		0x00000020
#define	 PN2_GRA_FRAME_IRQ0_ENA(irq)		((irq)<<3)
#define	 PN2_GRA_FRAME_IRQ0_ENA_MASK		0x00000008
#define	 PN2_GRA_FRAME_IRQ1_ENA(irq)		((irq)<<2)
#define	 PN2_GRA_FRAME_IRQ1_ENA_MASK		0x04000004
#define	 PN2_GRA_FF_UNDERFLOW_ENA(ff)		((ff)<<1)
#define	 PN2_GRA_FF_UNDERFLOW_ENA_MASK		0x00000002
#define	 PN2_VSYNC_IRQ_ENA(irq)			((irq)<<0)
#define	 PN2_SYNC_IRQ_ENA_MASK			0x00000001

#define gf0_imask(id)	((id) ? (((id) & 1) ? TV_FRAME_IRQ0_ENA_MASK \
		: PN2_GRA_FRAME_IRQ0_ENA_MASK) : GRA_FRAME_IRQ0_ENA_MASK)
#define gf1_imask(id)	((id) ? (((id) & 1) ? TV_FRAME_IRQ1_ENA_MASK \
		: PN2_GRA_FRAME_IRQ1_ENA_MASK) : GRA_FRAME_IRQ1_ENA_MASK)
#define vsync_imask(id)	((id) ? (((id) & 1) ? TVSYNC_IRQ_ENA_MASK \
		: PN2_SYNC_IRQ_ENA_MASK) : VSYNC_IRQ_ENA_MASK)
#define vsync_imasks	(vsync_imask(0) | vsync_imask(1))

#define display_done_imask(id)	((id) ? (((id) & 1) ? TV_FRAMEDONE_ENA_MASK\
	: (PN2_DMA_FRAME_IRQ0_ENA_MASK | PN2_DMA_FRAME_IRQ1_ENA_MASK))\
	: DUMB_FRAMEDONE_ENA_MASK)

#define display_done_imasks	(display_done_imask(0) | display_done_imask(1))

#define vf0_imask(id)	((id) ? (((id) & 1) ? TV_DMA_FRAME_IRQ0_ENA_MASK \
		: PN2_DMA_FRAME_IRQ0_ENA_MASK) : DMA_FRAME_IRQ0_ENA_MASK)
#define vf1_imask(id)	((id) ? (((id) & 1) ? TV_DMA_FRAME_IRQ1_ENA_MASK \
		: PN2_DMA_FRAME_IRQ1_ENA_MASK) : DMA_FRAME_IRQ1_ENA_MASK)

#define gfx_imasks	(gf0_imask(0) | gf1_imask(0) | gf0_imask(1) | \
		gf1_imask(1))
#define vid_imasks	(vf0_imask(0) | vf1_imask(0) | vf0_imask(1) | \
		vf1_imask(1))
#define vid_imask(id)	(display_done_imask(id))

#define pn1_imasks	(gf0_imask(0) | gf1_imask(0) | vsync_imask(0) | \
		display_done_imask(0) | vf0_imask(0) | vf1_imask(0))
#define tv_imasks	(gf0_imask(1) | gf1_imask(1) | vsync_imask(1) | \
		display_done_imask(1) | vf0_imask(1) | vf1_imask(1))
#define path_imasks(id)	((id) ? (tv_imasks) : (pn1_imasks))

/* error indications */
#define vid_udflow_imask(id)	((id) ? (((id) & 1) ? \
	(TV_DMA_FF_UNDERFLOW_ENA_MASK) : (PN2_DMA_FF_UNDERFLOW_ENA_MASK)) : \
	(DMA_FF_UNDERFLOW_ENA_MASK))
#define gfx_udflow_imask(id)	((id) ? (((id) & 1) ? \
	(TV_GRA_FF_UNDERFLOW_ENA_MASK) : (PN2_GRA_FF_UNDERFLOW_ENA_MASK)) : \
	(GRA_FF_UNDERFLOW_ENA_MASK))

#define err_imask(id) (vid_udflow_imask(id) | gfx_udflow_imask(id) | \
	AXI_BUS_ERROR_IRQ_ENA_MASK | AXI_LATENCY_TOO_LONG_IRQ_ENA_MASK)
#define err_imasks (err_imask(0) | err_imask(1) | err_imask(2))
/* LCD Interrupt Status Register */
#define SPU_IRQ_ISR			0x01C4
#define	 DMA_FRAME_IRQ0(irq)		((irq)<<31)
#define	 DMA_FRAME_IRQ0_MASK		0x80000000
#define	 DMA_FRAME_IRQ1(irq)		((irq)<<30)
#define	 DMA_FRAME_IRQ1_MASK		0x40000000
#define	 DMA_FF_UNDERFLOW(ff)		((ff)<<29)
#define	 DMA_FF_UNDERFLOW_MASK		0x20000000
#define	 AXI_BUS_ERROR_IRQ(irq)		((irq)<<28)
#define	 AXI_BUS_ERROR_IRQ_MASK		0x10000000
#define	 GRA_FRAME_IRQ0(irq)		((irq)<<27)
#define	 GRA_FRAME_IRQ0_MASK		0x08000000
#define	 GRA_FRAME_IRQ1(irq)		((irq)<<26)
#define	 GRA_FRAME_IRQ1_MASK		0x04000000
#define	 GRA_FF_UNDERFLOW(ff)		((ff)<<25)
#define	 GRA_FF_UNDERFLOW_MASK		0x02000000
#define	 VSYNC_IRQ(vsync_irq)		((vsync_irq)<<23)
#define	 VSYNC_IRQ_MASK			0x00800000
#define	 DUMB_FRAMEDONE(fdone)		((fdone)<<22)
#define	 DUMB_FRAMEDONE_MASK		0x00400000
#define	 TWC_FRAMEDONE(fdone)		((fdone)<<21)
#define	 TWC_FRAMEDONE_MASK		0x00200000
#define	 HWC_FRAMEDONE(fdone)		((fdone)<<20)
#define	 HWC_FRAMEDONE_MASK		0x00100000
#define	 SLV_IRQ(irq)			((irq)<<19)
#define	 SLV_IRQ_MASK			0x00080000
#define	 SPI_IRQ(irq)			((irq)<<18)
#define	 SPI_IRQ_MASK			0x00040000
#define	 PWRDN_IRQ(irq)			((irq)<<17)
#define	 PWRDN_IRQ_MASK			0x00020000
#define	 AXI_LATENCY_TOO_LONGR_IRQ(irq)	((irq)<<16)
#define	 AXI_LATENCY_TOO_LONGR_IRQ_MASK	0x00010000
#define	 TV_DMA_FRAME_IRQ0(irq)		((irq)<<15)
#define	 TV_DMA_FRAME_IRQ0_MASK		0x00008000
#define	 TV_DMA_FRAME_IRQ1(irq)		((irq)<<14)
#define	 TV_DMA_FRAME_IRQ1_MASK		0x00004000
#define	 TV_DMA_FF_UNDERFLOW(unerrun)	((unerrun)<<13)
#define	 TV_DMA_FF_UNDERFLOW_MASK	0x00002000
#define	 TVSYNC_IRQ(irq)		((irq)<<12)
#define	 TVSYNC_IRQ_MASK		0x00001000
#define	 TV_FRAME_IRQ0(irq)		((irq)<<11)
#define	 TV_FRAME_IRQ0_MASK		0x00000800
#define	 TV_FRAME_IRQ1(irq)		((irq)<<10)
#define	 TV_FRAME_IRQ1_MASK		0x00000400
#define	 TV_GRA_FF_UNDERFLOW(unerrun)	((unerrun)<<9)
#define	 TV_GRA_FF_UNDERFLOW_MASK	0x00000200
#define	 PN2_DMA_FRAME_IRQ0(irq)	((irq)<<7)
#define	 PN2_DMA_FRAME_IRQ0_MASK	0x00000080
#define	 PN2_DMA_FRAME_IRQ1(irq)	((irq)<<6)
#define	 PN2_DMA_FRAME_IRQ1_MASK	0x00000040
#define	 PN2_DMA_FF_UNDERFLOW(ff)	((ff)<<5)
#define	 PN2_DMA_FF_UNDERFLOW_MASK	0x00000020
#define	 PN2_GRA_FRAME_IRQ0(irq)	((irq)<<3)
#define	 PN2_GRA_FRAME_IRQ0_MASK	0x00000008
#define	 PN2_GRA_FRAME_IRQ1(irq)	((irq)<<2)
#define	 PN2_GRA_FRAME_IRQ1_MASK	0x04000004
#define	 PN2_GRA_FF_UNDERFLOW(ff)	((ff)<<1)
#define	 PN2_GRA_FF_UNDERFLOW_MASK	0x00000002
#define	 PN2_VSYNC_IRQ(irq)		((irq)<<0)
#define	 PN2_SYNC_IRQ_MASK		0x00000001

/* LCD FIFO Depth register */
#define LCD_FIFO_DEPTH			0x01c8
#define	 VIDEO_FIFO(fi)			((fi) << 0)
#define	 VIDEO_FIFO_MASK		0x00000003
#define	 GRAPHIC_FIFO(fi)		((fi) << 2)
#define	 GRAPHIC_FIFO_MASK		0x0000000c

/* read-only */
#define	 DMA_FRAME_IRQ0_LEVEL_MASK		0x00008000
#define	 DMA_FRAME_IRQ1_LEVEL_MASK		0x00004000
#define	 DMA_FRAME_CNT_ISR_MASK			0x00003000
#define	 GRA_FRAME_IRQ0_LEVEL_MASK		0x00000800
#define	 GRA_FRAME_IRQ1_LEVEL_MASK		0x00000400
#define	 GRA_FRAME_CNT_ISR_MASK			0x00000300
#define	 VSYNC_IRQ_LEVEL_MASK			0x00000080
#define	 DUMB_FRAMEDONE_LEVEL_MASK		0x00000040
#define	 TWC_FRAMEDONE_LEVEL_MASK		0x00000020
#define	 HWC_FRAMEDONE_LEVEL_MASK		0x00000010
#define	 SLV_FF_EMPTY_MASK			0x00000008
#define	 DMA_FF_ALLEMPTY_MASK			0x00000004
#define	 GRA_FF_ALLEMPTY_MASK			0x00000002
#define	 PWRDN_IRQ_LEVEL_MASK			0x00000001

/* 32 bit LCD Interrupt Reset Status*/
#define SPU_IRQ_RSR				(0x01C8)
/* 32 bit Panel Path Graphic Partial Display Horizontal Control Register*/
#define LCD_GRA_CUTHPXL				(0x01CC)
/* 32 bit Panel Path Graphic Partial Display Vertical Control Register*/
#define LCD_GRA_CUTVLN				(0x01D0)
/* 32 bit TV Path Graphic Partial Display	  Horizontal Control Register*/
#define LCD_TVG_CUTHPXL				(0x01D4)
/* 32 bit TV Path Graphic Partial Display Vertical Control Register*/
#define LCD_TVG_CUTVLN				(0x01D8)
/* 32 bit LCD Global Control Register*/
#define LCD_TOP_CTRL				(0x01DC)
/* 32 bit LCD SQU Line Buffer Control Register 1*/
#define LCD_SQULN1_CTRL				(0x01E0)
/* 32 bit LCD SQU Line Buffer Control Register 2*/
#define LCD_SQULN2_CTRL				(0x01E4)
#define squln_ctrl(id)	((id) ? (((id) & 1) ? LCD_SQULN2_CTRL : \
			LCD_PN2_SQULN1_CTRL) : LCD_SQULN1_CTRL)

/* 32 bit LCD Mixed Overlay Control Register */
#define LCD_AFA_ALL2ONE				(0x01E8)

#define LCD_PN2_SCLK_DIV			(0x01EC)
#define LCD_PN2_TCLK_DIV			(0x01F0)
#define LCD_LVDS_SCLK_DIV_WR			(0x01F4)
#define LCD_LVDS_SCLK_DIV_RD			(0x01FC)
#define PN2_LCD_DMA_START_ADDR_Y0		(0x0200)
#define PN2_LCD_DMA_START_ADDR_U0		(0x0204)
#define PN2_LCD_DMA_START_ADDR_V0		(0x0208)
#define PN2_LCD_DMA_START_ADDR_C0		(0x020C)
#define PN2_LCD_DMA_START_ADDR_Y1		(0x0210)
#define PN2_LCD_DMA_START_ADDR_U1		(0x0214)
#define PN2_LCD_DMA_START_ADDR_V1		(0x0218)
#define PN2_LCD_DMA_START_ADDR_C1		(0x021C)
#define PN2_LCD_DMA_PITCH_YC			(0x0220)
#define PN2_LCD_DMA_PITCH_UV			(0x0224)
#define PN2_LCD_DMA_OVSA_HPXL_VLN		(0x0228)
#define PN2_LCD_DMA_HPXL_VLN			(0x022C)
#define PN2_LCD_DMAZM_HPXL_VLN			(0x0230)
#define PN2_LCD_GRA_START_ADDR0			(0x0234)
#define PN2_LCD_GRA_START_ADDR1			(0x0238)
#define PN2_LCD_GRA_PITCH			(0x023C)
#define PN2_LCD_GRA_OVSA_HPXL_VLN		(0x0240)
#define PN2_LCD_GRA_HPXL_VLN			(0x0244)
#define PN2_LCD_GRAZM_HPXL_VLN			(0x0248)
#define PN2_LCD_HWC_OVSA_HPXL_VLN		(0x024C)
#define PN2_LCD_HWC_HPXL_VLN			(0x0250)
#define LCD_PN2_V_H_TOTAL			(0x0254)
#define LCD_PN2_V_H_ACTIVE			(0x0258)
#define LCD_PN2_H_PORCH				(0x025C)
#define LCD_PN2_V_PORCH				(0x0260)
#define LCD_PN2_BLANKCOLOR			(0x0264)
#define LCD_PN2_ALPHA_COLOR1			(0x0268)
#define LCD_PN2_ALPHA_COLOR2			(0x026C)
#define LCD_PN2_COLORKEY_Y			(0x0270)
#define LCD_PN2_COLORKEY_U			(0x0274)
#define LCD_PN2_COLORKEY_V			(0x0278)
#define LCD_PN2_SEPXLCNT			(0x027C)
#define LCD_TV_V_H_TOTAL_FLD			(0x0280)
#define LCD_TV_V_PORCH_FLD			(0x0284)
#define LCD_TV_SEPXLCNT_FLD			(0x0288)

#define LCD_2ND_ALPHA				(0x0294)
#define LCD_PN2_CONTRAST			(0x0298)
#define LCD_PN2_SATURATION			(0x029c)
#define LCD_PN2_CBSH_HUE			(0x02a0)
#define LCD_TIMING_EXT				(0x02C0)
#define LCD_PN2_LAYER_ALPHA_SEL1		(0x02c4)
#define LCD_PN2_CTRL0				(0x02C8)
#define TV_LAYER_ALPHA_SEL1			(0x02cc)
#define LCD_SMPN2_CTRL				(0x02D0)
#define LCD_IO_OVERL_MAP_CTRL			(0x02D4)
#define LCD_DUMB2_CTRL				(0x02d8)
#define LCD_PN2_CTRL1				(0x02DC)
#define PN2_IOPAD_CONTROL			(0x02E0)
#define LCD_PN2_SQULN1_CTRL			(0x02E4)
#define PN2_LCD_GRA_CUTHPXL			(0x02e8)
#define PN2_LCD_GRA_CUTVLN			(0x02ec)
#define LCD_PN2_SQULN2_CTRL			(0x02F0)
#define ALL_LAYER_ALPHA_SEL			(0x02F4)

/* pxa988 has different MASTER_CTRL from MMP3/MMP2 */
#ifdef CONFIG_CPU_PXA988
#define TIMING_MASTER_CONTROL			(0x01F4)
#define MASTER_ENH(id)				(1 << ((id) + 5))
#define MASTER_ENV(id)				(1 << ((id) + 6))
#else
#define TIMING_MASTER_CONTROL			(0x02F8)
#define MASTER_ENH(id)				(1 << (id))
#define MASTER_ENV(id)				(1 << ((id) + 4))
#endif

#define DSI_START_SEL_SHIFT(id)		(((id) << 1) + 8)
#define timing_master_config(path, dsi_id, lcd_id) \
	(MASTER_ENH(path) | MASTER_ENV(path) | \
	(((lcd_id) + ((dsi_id) << 1)) << DSI_START_SEL_SHIFT(path)))

#define LCD_2ND_BLD_CTL				(0x02Fc)
#define LVDS_SRC_MASK				(3 << 30)
#define LVDS_SRC_SHIFT				(30)
#define LVDS_FMT_MASK				(1 << 28)
#define LVDS_FMT_SHIFT				(28)

#define CLK_SCLK	(1 << 0)
#define CLK_LVDS_RD	(1 << 1)
#define CLK_LVDS_WR	(1 << 2)

#define gra_partdisp_ctrl_hor(id)	((id) ? (((id) & 1) ? \
	LCD_TVG_CUTHPXL : PN2_LCD_GRA_CUTHPXL) : LCD_GRA_CUTHPXL)
#define gra_partdisp_ctrl_ver(id)	((id) ? (((id) & 1) ? \
	LCD_TVG_CUTVLN : PN2_LCD_GRA_CUTVLN) : LCD_GRA_CUTVLN)

/*
 * defined Video Memory Color format for DMA control 0 register
 * DMA0 bit[23:20]
 */
#define VMODE_RGB565		0x0
#define VMODE_RGB1555		0x1
#define VMODE_RGB888PACKED	0x2
#define VMODE_RGB888UNPACKED	0x3
#define VMODE_RGBA888		0x4
#define VMODE_YUV422PACKED	0x5
#define VMODE_YUV422PLANAR	0x6
#define VMODE_YUV420PLANAR	0x7
#define VMODE_SMPNCMD		0x8
#define VMODE_PALETTE4BIT	0x9
#define VMODE_PALETTE8BIT	0xa
#define VMODE_RESERVED		0xb

/*
 * defined Graphic Memory Color format for DMA control 0 register
 * DMA0 bit[19:16]
 */
#define GMODE_RGB565		0x0
#define GMODE_RGB1555		0x1
#define GMODE_RGB888PACKED	0x2
#define GMODE_RGB888UNPACKED	0x3
#define GMODE_RGBA888		0x4
#define GMODE_YUV422PACKED	0x5
#define GMODE_YUV422PLANAR	0x6
#define GMODE_YUV420PLANAR	0x7
#define GMODE_SMPNCMD		0x8
#define GMODE_PALETTE4BIT	0x9
#define GMODE_PALETTE8BIT	0xa
#define GMODE_RESERVED		0xb

/*
 * define for DMA control 1 register
 */
#define DMA1_FRAME_TRIG		31 /* bit location */
#define DMA1_VSYNC_MODE		28
#define DMA1_VSYNC_INV		27
#define DMA1_CKEY		24
#define DMA1_CARRY		23
#define DMA1_LNBUF_ENA		22
#define DMA1_GATED_ENA		21
#define DMA1_PWRDN_ENA		20
#define DMA1_DSCALE		18
#define DMA1_ALPHA_MODE		16
#define DMA1_ALPHA		08
#define DMA1_PXLCMD		00

/*
 * defined for Configure Dumb Mode
 * DUMB LCD Panel bit[31:28]
 */
#define DUMB16_RGB565_0		0x0
#define DUMB16_RGB565_1		0x1
#define DUMB18_RGB666_0		0x2
#define DUMB18_RGB666_1		0x3
#define DUMB12_RGB444_0		0x4
#define DUMB12_RGB444_1		0x5
#define DUMB24_RGB888_0		0x6
#define DUMB_BLANK		0x7

/*
 * defined for Configure I/O Pin Allocation Mode
 * LCD LCD I/O Pads control register bit[3:0]
 */
#define IOPAD_DUMB24		0x0
#define IOPAD_DUMB18SPI		0x1
#define IOPAD_DUMB18GPIO	0x2
#define IOPAD_DUMB16SPI		0x3
#define IOPAD_DUMB16GPIO	0x4
#define IOPAD_DUMB12		0x5
#define IOPAD_SMART18SPI	0x6
#define IOPAD_SMART16SPI	0x7
#define IOPAD_SMART8BOTH	0x8
#define IOPAD_DUMB18_SMART8	0x9
#define IOPAD_DUMB16_SMART8SPI	0xa
#define IOPAD_DUMB16_SMART8GPIO	0xb
#define IOPAD_DUMB16_DUMB16	0xc
#define IOPAD_SMART8_SMART8	0xc

/*
 *defined for indicating boundary and cycle burst length
 */
#define  CFG_BOUNDARY_1KB			(1<<5)
#define  CFG_BOUNDARY_4KB			(0<<5)
#define	 CFG_CYC_BURST_LEN16			(1<<4)
#define	 CFG_CYC_BURST_LEN8			(0<<4)

/*
 * defined Dumb Panel Clock Divider register
 * SCLK_Source bit[31]
 */
 /* 0: PLL clock select*/
#define AXI_BUS_SEL			0x80000000
#define CCD_CLK_SEL			0x40000000
#define DCON_CLK_SEL			0x20000000
#define ENA_CLK_INT_DIV			CONFIG_FB_DOVE_CLCD_SCLK_DIV
#define IDLE_CLK_INT_DIV		0x1	  /* idle Integer Divider */
#define DIS_CLK_INT_DIV			0x0	  /* Disable Integer Divider */

/* SRAM ID */
#define SRAMID_GAMMA_YR			0x0
#define SRAMID_GAMMA_UG			0x1
#define SRAMID_GAMMA_VB			0x2
#define SRAMID_PALATTE			0x3
#define SRAMID_HWC			0xf

/* SRAM INIT Read/Write */
#define SRAMID_INIT_READ		0x0
#define SRAMID_INIT_WRITE		0x2
#define SRAMID_INIT_DEFAULT		0x3

/*
 * defined VSYNC selection mode for DMA control 1 register
 * DMA1 bit[30:28]
 */
#define VMODE_SMPN			0x0
#define VMODE_SMPNIRQ			0x1
#define VMODE_DUMB			0x2
#define VMODE_IPE			0x3
#define VMODE_IRE			0x4

/*
 * defined Configure Alpha and Alpha mode for DMA control 1 register
 * DMA1 bit[15:08](alpha) / bit[17:16](alpha mode)
 */
/* ALPHA mode */
#define MODE_ALPHA_DMA			0x0
#define MODE_ALPHA_GRA			0x1
#define MODE_ALPHA_CFG			0x2

/* alpha value */
#define ALPHA_NOGRAPHIC			0xFF	  /* all video, no graphic */
#define ALPHA_NOVIDEO			0x00	  /* all graphic, no video */
#define ALPHA_GRAPHNVIDEO		0x0F	  /* Selects graphic & video */

/*
 * defined Pixel Command for DMA control 1 register
 * DMA1 bit[07:00]
 */
#define PIXEL_CMD			0x81

/* DSI */
/* DSI1 - 4 Lane Controller base */
#define DSI1_REGS_PHYSICAL_BASE		0xD420B800
/* DSI2 - 3 Lane Controller base */
#define DSI2_REGS_PHYSICAL_BASE		0xD420BA00

/*	   DSI Controller Registers	   */
struct dsi_lcd_regs {
#define DSI_LCD1_CTRL_0  0x100   /* DSI Active Panel 1 Control register 0 */
#define DSI_LCD1_CTRL_1  0x104   /* DSI Active Panel 1 Control register 1 */
	u32 ctrl0;
	u32 ctrl1;
	u32 reserved1[2];

#define DSI_LCD1_TIMING_0		0x110   /* Timing register 0 */
#define DSI_LCD1_TIMING_1		0x114   /* Timing register 1 */
#define DSI_LCD1_TIMING_2		0x118   /* Timing register 2 */
#define DSI_LCD1_TIMING_3		0x11C   /* Timing register 3 */
#define DSI_LCD1_WC_0			0x120   /* Word Count register 0 */
#define DSI_LCD1_WC_1			0x124   /* Word Count register 1 */
#define DSI_LCD1_WC_2			0x128	 /* Word Count register 2 */
	u32 timing0;
	u32 timing1;
	u32 timing2;
	u32 timing3;
	u32 wc0;
	u32 wc1;
	u32 wc2;
	u32 reserved2[1];
	u32 slot_cnt0;
	u32 slot_cnt1;
	u32 reserved3[2];
	u32 status_0;
	u32 status_1;
	u32 status_2;
	u32 status_3;
	u32 status_4;
};

struct dsi_regs {
#define DSI_CTRL_0	  0x000   /* DSI control register 0 */
#define DSI_CTRL_1	  0x004   /* DSI control register 1 */
	u32 ctrl0;
	u32 ctrl1;
	u32 reserved1[2];
	u32 irq_status;
	u32 irq_mask;
	u32 reserved2[2];

#define DSI_CPU_CMD_0   0x020   /* DSI CPU packet command register 0 */
#define DSI_CPU_CMD_1   0x024   /* DSU CPU Packet Command Register 1 */
#define DSI_CPU_CMD_3	0x02C   /* DSU CPU Packet Command Register 3 */
#define DSI_CPU_WDAT_0	0x030   /* DSI CUP */
	u32 cmd0;
	u32 cmd1;
	u32 cmd2;
	u32 cmd3;
	u32 dat0;
	u32 status0;
	u32 status1;
	u32 status2;
	u32 status3;
	u32 status4;
	u32 reserved3[2];

	u32 smt_cmd;
	u32 smt_ctrl0;
	u32 smt_ctrl1;
	u32 reserved4[1];

	u32 rx0_status;

/* Rx Packet Header - data from slave device */
#define DSI_RX_PKT_HDR_0 0x064
	u32 rx0_header;
	u32 rx1_status;
	u32 rx1_header;
	u32 rx_ctrl;
	u32 rx_ctrl1;
	u32 rx2_status;
	u32 rx2_header;
	u32 reserved5[1];

	u32 phy_ctrl1;
#define DSI_PHY_CTRL_2		0x088   /* DSI DPHI Control Register 2 */
#define DSI_PHY_CTRL_3		0x08C   /* DPHY Control Register 3 */
	u32 phy_ctrl2;
	u32 phy_ctrl3;
	u32 phy_status0;
	u32 phy_status1;
	u32 reserved6[5];
	u32 phy_status2;

#define DSI_PHY_RCOMP_0		0x0B0   /* DPHY Rcomp Control Register */
	u32 phy_rcomp0;
	u32 reserved7[3];
#define DSI_PHY_TIME_0		0x0C0   /* DPHY Timing Control Register 0 */
#define DSI_PHY_TIME_1		0x0C4   /* DPHY Timing Control Register 1 */
#define DSI_PHY_TIME_2		0x0C8   /* DPHY Timing Control Register 2 */
#define DSI_PHY_TIME_3		0x0CC   /* DPHY Timing Control Register 3 */
#define DSI_PHY_TIME_4		0x0D0   /* DPHY Timing Control Register 4 */
#define DSI_PHY_TIME_5		0x0D4   /* DPHY Timing Control Register 5 */
	u32 phy_timing0;
	u32 phy_timing1;
	u32 phy_timing2;
	u32 phy_timing3;
	u32 phy_code_0;
	u32 phy_code_1;
	u32 reserved8[2];
	u32 mem_ctrl;
	u32 tx_timer;
	u32 rx_timer;
	u32 turn_timer;
	u32 reserved9[4];

#define DSI_LCD1_CTRL_0  0x100   /* DSI Active Panel 1 Control register 0 */
#define DSI_LCD1_CTRL_1  0x104   /* DSI Active Panel 1 Control register 1 */
#define DSI_LCD1_TIMING_0		0x110   /* Timing register 0 */
#define DSI_LCD1_TIMING_1		0x114   /* Timing register 1 */
#define DSI_LCD1_TIMING_2		0x118   /* Timing register 2 */
#define DSI_LCD1_TIMING_3		0x11C   /* Timing register 3 */
#define DSI_LCD1_WC_0			0x120   /* Word Count register 0 */
#define DSI_LCD1_WC_1			0x124   /* Word Count register 1 */
#define DSI_LCD1_WC_2			0x128   /* Word Count register 2 */
	struct dsi_lcd_regs lcd1;
	u32 reserved10[11];
	struct dsi_lcd_regs lcd2;
};

#define DSI_LCD2_CTRL_0  0x180   /* DSI Active Panel 2 Control register 0 */
#define DSI_LCD2_CTRL_1  0x184   /* DSI Active Panel 2 Control register 1 */
#define DSI_LCD2_TIMING_0		0x190   /* Timing register 0 */
#define DSI_LCD2_TIMING_1		0x194   /* Timing register 1 */
#define DSI_LCD2_TIMING_2		0x198   /* Timing register 2 */
#define DSI_LCD2_TIMING_3		0x19C   /* Timing register 3 */
#define DSI_LCD2_WC_0			0x1A0   /* Word Count register 0 */
#define DSI_LCD2_WC_1			0x1A4   /* Word Count register 1 */
#define DSI_LCD2_WC_2			0x1A8	 /* Word Count register 2 */

/*	DSI_CTRL_0		0x0000	DSI Control Register 0 */
#define DSI_CTRL_0_CFG_SOFT_RST			(1<<31)
#define DSI_CTRL_0_CFG_SOFT_RST_REG		(1<<30)
#define DSI_CTRL_0_CFG_LCD1_TX_EN		(1<<8)
#define DSI_CTRL_0_CFG_LCD1_SLV			(1<<4)
#define DSI_CTRL_0_CFG_LCD1_EN			(1<<0)

/*	DSI_CTRL_1		0x0004	DSI Control Register 1 */
#define DSI_CTRL_1_CFG_EOTP			(1<<8)
#define DSI_CTRL_1_CFG_RSVD			(2<<4)
#define DSI_CTRL_1_CFG_LCD2_VCH_NO_MASK		(3<<2)
#define DSI_CTRL_1_CFG_LCD2_VCH_NO_SHIFT	2
#define DSI_CTRL_1_CFG_LCD1_VCH_NO_MASK		(3<<0)
#define DSI_CTRL_1_CFG_LCD1_VCH_NO_SHIFT	0

/*	DSI_LCD1_CTRL_1	0x0104	DSI Active Panel 1 Control Register 1 */
/* LCD 1 Vsync Reset Enable */
#define	DSI_LCD1_CTRL_1_CFG_L1_VSYNC_RST_EN	(1<<31)
/* LCD 1 2K Pixel Buffer Mode Enable */
#define	DSI_LCD1_CTRL_1_CFG_L1_M2K_EN		(1<<30)
/*		Bit(s) DSI_LCD1_CTRL_1_RSRV_29_23 reserved */
/* Long Blanking Packet Enable */
#define	DSI_LCD1_CTRL_1_CFG_L1_HLP_PKT_EN	(1<<22)
/* Extra Long Blanking Packet Enable */
#define	DSI_LCD1_CTRL_1_CFG_L1_HEX_PKT_EN	(1<<21)
/* Front Porch Packet Enable */
#define	DSI_LCD1_CTRL_1_CFG_L1_HFP_PKT_EN	(1<<20)
/* hact Packet Enable */
#define	DSI_LCD1_CTRL_1_CFG_L1_HACT_PKT_EN	(1<<19)
/* Back Porch Packet Enable */
#define	DSI_LCD1_CTRL_1_CFG_L1_HBP_PKT_EN	(1<<18)
/* hse Packet Enable */
#define	DSI_LCD1_CTRL_1_CFG_L1_HSE_PKT_EN	(1<<17)
/* hsa Packet Enable */
#define	DSI_LCD1_CTRL_1_CFG_L1_HSA_PKT_EN	(1<<16)
/* All Item Enable after Pixel Data */
#define	DSI_LCD1_CTRL_1_CFG_L1_ALL_SLOT_EN	(1<<15)
/* Extra Long Packet Enable after Pixel Data */
#define	DSI_LCD1_CTRL_1_CFG_L1_HEX_SLOT_EN	(1<<14)
/*		Bit(s) DSI_LCD1_CTRL_1_RSRV_13_11 reserved */
/* Turn Around Bus at Last h Line */
#define	DSI_LCD1_CTRL_1_CFG_L1_LAST_LINE_TURN	(1<<10)
/* Go to Low Power Every Frame */
#define	DSI_LCD1_CTRL_1_CFG_L1_LPM_FRAME_EN	(1<<9)
/* Go to Low Power Every Line */
#define	DSI_LCD1_CTRL_1_CFG_L1_LPM_LINE_EN	(1<<8)
/*		Bit(s) DSI_LCD1_CTRL_1_RSRV_7_4 reserved */
/* DSI Transmission Mode for LCD 1 */
#define DSI_LCD1_CTRL_1_CFG_L1_BURST_MODE_SHIFT	2
#define DSI_LCD1_CTRL_1_CFG_L1_BURST_MODE_MASK	(3<<2)
/* LCD 1 Input Data RGB Mode for LCD 1 */
#define DSI_LCD2_CTRL_1_CFG_L1_RGB_TYPE_SHIFT	0
#define DSI_LCD2_CTRL_1_CFG_L1_RGB_TYPE_MASK	(3<<2)

/*	DSI_PHY_CTRL_2		0x0088	DPHY Control Register 2 */
/*		Bit(s) DSI_PHY_CTRL_2_RSRV_31_12 reserved */
/* DPHY LP Receiver Enable */
#define	DSI_PHY_CTRL_2_CFG_CSR_LANE_RESC_EN_MASK	(0xf<<8)
#define	DSI_PHY_CTRL_2_CFG_CSR_LANE_RESC_EN_SHIFT	8
/* DPHY Data Lane Enable */
#define	DSI_PHY_CTRL_2_CFG_CSR_LANE_EN_MASK		(0xf<<4)
#define	DSI_PHY_CTRL_2_CFG_CSR_LANE_EN_SHIFT		4
/* DPHY Bus Turn Around */
#define	DSI_PHY_CTRL_2_CFG_CSR_LANE_TURN_MASK		(0xf)
#define	DSI_PHY_CTRL_2_CFG_CSR_LANE_TURN_SHIFT		0

/*	DSI_CPU_CMD_1		0x0024	DSI CPU Packet Command Register 1 */
/*		Bit(s) DSI_CPU_CMD_1_RSRV_31_24 reserved */
/* LPDT TX Enable */
#define	DSI_CPU_CMD_1_CFG_TXLP_LPDT_MASK		(0xf<<20)
#define	DSI_CPU_CMD_1_CFG_TXLP_LPDT_SHIFT		20
/* ULPS TX Enable */
#define	DSI_CPU_CMD_1_CFG_TXLP_ULPS_MASK		(0xf<<16)
#define	DSI_CPU_CMD_1_CFG_TXLP_ULPS_SHIFT		16
/* Low Power TX Trigger Code */
#define	DSI_CPU_CMD_1_CFG_TXLP_TRIGGER_CODE_MASK	(0xffff)
#define	DSI_CPU_CMD_1_CFG_TXLP_TRIGGER_CODE_SHIFT	0

/*	DSI_PHY_TIME_0	0x00c0	DPHY Timing Control Register 0 */
/* Length of HS Exit Period in tx_clk_esc Cycles */
#define	DSI_PHY_TIME_0_CFG_CSR_TIME_HS_EXIT_MASK	(0xff<<24)
#define	DSI_PHY_TIME_0_CFG_CSR_TIME_HS_EXIT_SHIFT	24
/* DPHY HS Trail Period Length */
#define	DSI_PHY_TIME_0_CFG_CSR_TIME_HS_TRAIL_MASK	(0xff<<16)
#define	DSI_PHY_TIME_0_CFG_CSR_TIME_HS_TRAIL_SHIFT	16
/* DPHY HS Zero State Length */
#define	DSI_PHY_TIME_0_CDG_CSR_TIME_HS_ZERO_MASK	(0xff<<8)
#define	DSI_PHY_TIME_0_CDG_CSR_TIME_HS_ZERO_SHIFT	8
/* DPHY HS Prepare State Length */
#define	DSI_PHY_TIME_0_CFG_CSR_TIME_HS_PREP_MASK	(0xff)
#define	DSI_PHY_TIME_0_CFG_CSR_TIME_HS_PREP_SHIFT	0

/*	DSI_PHY_TIME_1		0x00c4	DPHY Timing Control Register 1 */
/* Time to Drive LP-00 by New Transmitter */
#define	DSI_PHY_TIME_1_CFG_CSR_TIME_TA_GET_MASK		(0xff<<24)
#define	DSI_PHY_TIME_1_CFG_CSR_TIME_TA_GET_SHIFT	24
/* Time to Drive LP-00 after Turn Request */
#define	DSI_PHY_TIME_1_CFG_CSR_TIME_TA_GO_MASK		(0xff<<16)
#define	DSI_PHY_TIME_1_CFG_CSR_TIME_TA_GO_SHIFT		16
/* DPHY HS Wakeup Period Length */
#define	DSI_PHY_TIME_1_CFG_CSR_TIME_WAKEUP_MASK		(0xffff)
#define	DSI_PHY_TIME_1_CFG_CSR_TIME_WAKEUP_SHIFT	0

/*	DSI_PHY_TIME_2		0x00c8	DPHY Timing Control Register 2 */
/* DPHY CLK Exit Period Length */
#define	DSI_PHY_TIME_2_CFG_CSR_TIME_CK_EXIT_MASK	(0xff<<24)
#define	DSI_PHY_TIME_2_CFG_CSR_TIME_CK_EXIT_SHIFT	24
/* DPHY CLK Trail Period Length */
#define	DSI_PHY_TIME_2_CFG_CSR_TIME_CK_TRAIL_MASK	(0xff<<16)
#define	DSI_PHY_TIME_2_CFG_CSR_TIME_CK_TRAIL_SHIFT	16
/* DPHY CLK Zero State Length */
#define	DSI_PHY_TIME_2_CFG_CSR_TIME_CK_ZERO_MASK	(0xff<<8)
#define	DSI_PHY_TIME_2_CFG_CSR_TIME_CK_ZERO_SHIFT	8
/* DPHY CLK LP Length */
#define	DSI_PHY_TIME_2_CFG_CSR_TIME_CK_LPX_MASK		(0xff)
#define	DSI_PHY_TIME_2_CFG_CSR_TIME_CK_LPX_SHIFT	0

/*	DSI_PHY_TIME_3		0x00cc	DPHY Timing Control Register 3 */
/*		Bit(s) DSI_PHY_TIME_3_RSRV_31_16 reserved */
/* DPHY LP Length */
#define	DSI_PHY_TIME_3_CFG_CSR_TIME_LPX_MASK		(0xff<<8)
#define	DSI_PHY_TIME_3_CFG_CSR_TIME_LPX_SHIFT		8
/* DPHY HS req to rdy Length */
#define	DSI_PHY_TIME_3_CFG_CSR_TIME_REQRDY_MASK		(0xff)
#define	DSI_PHY_TIME_3_CFG_CSR_TIME_REQRDY_SHIFT	0

/*
 * DSI timings
 * PXA988 has diffrent ESC CLK with MMP2/MMP3
 * it will be used in dsi_set_dphy() in pxa688_phy.c
 * as low power mode clock.
 */
#ifdef CONFIG_CPU_PXA988
#define DSI_ESC_CLK				52  /* Unit: Mhz */
#define DSI_ESC_CLK_T				19  /* Unit: ns */
#else
#define DSI_ESC_CLK				66  /* Unit: Mhz */
#define DSI_ESC_CLK_T				15  /* Unit: ns */
#endif

/* LVDS */
/* LVDS_PHY_CTRL */
#define LVDS_PHY_CTL				0x2A4
#define LVDS_PLL_LOCK				(1 << 31)
#define LVDS_PHY_EXT_MASK			(7 << 28)
#define LVDS_PHY_EXT_SHIFT			(28)
#define LVDS_CLK_PHASE_MASK			(0x7f << 16)
#define LVDS_CLK_PHASE_SHIFT			(16)
#define LVDS_SSC_RESET_EXT			(1 << 13)
#define LVDS_SSC_MODE_DOWN_SPREAD		(1 << 12)
#define LVDS_SSC_EN				(1 << 11)
#define LVDS_PU_PLL				(1 << 10)
#define LVDS_PU_TX				(1 << 9)
#define LVDS_PU_IVREF				(1 << 8)
#define LVDS_CLK_SEL				(1 << 7)
#define LVDS_CLK_SEL_LVDS_PCLK			(1 << 7)
#define LVDS_PD_CH_MASK				(0x3f << 1)
#define LVDS_PD_CH(ch)				((ch) << 1)
#define LVDS_RST				(1 << 0)

#define LVDS_PHY_CTL_EXT	0x2A8

/* LVDS_PHY_CTRL_EXT1 */
#define LVDS_SSC_RNGE_MASK			(0x7ff << 16)
#define LVDS_SSC_RNGE_SHIFT			(16)
#define LVDS_RESERVE_IN_MASK			(0xf << 12)
#define LVDS_RESERVE_IN_SHIFT			(12)
#define LVDS_TEST_MON_MASK			(0x7 << 8)
#define LVDS_TEST_MON_SHIFT			(8)
#define LVDS_POL_SWAP_MASK			(0x3f << 0)
#define LVDS_POL_SWAP_SHIFT			(0)

/* LVDS_PHY_CTRL_EXT2 */
#define LVDS_TX_DIF_AMP_MASK			(0xf << 24)
#define LVDS_TX_DIF_AMP_SHIFT			(24)
#define LVDS_TX_DIF_CM_MASK			(0x3 << 22)
#define LVDS_TX_DIF_CM_SHIFT			(22)
#define LVDS_SELLV_TXCLK_MASK			(0x1f << 16)
#define LVDS_SELLV_TXCLK_SHIFT			(16)
#define LVDS_TX_CMFB_EN				(0x1 << 15)
#define LVDS_TX_TERM_EN				(0x1 << 14)
#define LVDS_SELLV_TXDATA_MASK			(0x1f << 8)
#define LVDS_SELLV_TXDATA_SHIFT			(8)
#define LVDS_SELLV_OP7_MASK			(0x3 << 6)
#define LVDS_SELLV_OP7_SHIFT			(6)
#define LVDS_SELLV_OP6_MASK			(0x3 << 4)
#define LVDS_SELLV_OP6_SHIFT			(4)
#define LVDS_SELLV_OP9_MASK			(0x3 << 2)
#define LVDS_SELLV_OP9_SHIFT			(2)
#define LVDS_STRESSTST_EN			(0x1 << 0)

/* LVDS_PHY_CTRL_EXT3 */
#define LVDS_KVCO_MASK				(0xf << 28)
#define LVDS_KVCO_SHIFT				(28)
#define LVDS_CTUNE_MASK				(0x3 << 26)
#define LVDS_CTUNE_SHIFT			(26)
#define LVDS_VREG_IVREF_MASK			(0x3 << 24)
#define LVDS_VREG_IVREF_SHIFT			(24)
#define LVDS_VDDL_MASK				(0xf << 20)
#define LVDS_VDDL_SHIFT				(20)
#define LVDS_VDDM_MASK				(0x3 << 18)
#define LVDS_VDDM_SHIFT				(18)
#define LVDS_FBDIV_MASK				(0xf << 8)
#define LVDS_FBDIV_SHIFT			(8)
#define LVDS_REFDIV_MASK			(0x7f << 0)
#define LVDS_REFDIV_SHIFT			(0)

/* LVDS_PHY_CTRL_EXT4 */
#define LVDS_SSC_FREQ_DIV_MASK			(0xffff << 16)
#define LVDS_SSC_FREQ_DIV_SHIFT			(16)
#define LVDS_INTPI_MASK				(0xf << 12)
#define LVDS_INTPI_SHIFT			(12)
#define LVDS_VCODIV_SEL_SE_MASK			(0xf << 8)
#define LVDS_VCODIV_SEL_SE_SHIFT		(8)
#define LVDS_RESET_INTP_EXT			(0x1 << 7)
#define LVDS_VCO_VRNG_MASK			(0x7 << 4)
#define LVDS_VCO_VRNG_SHIFT			(4)
#define LVDS_PI_EN				(0x1 << 3)
#define LVDS_ICP_MASK				(0x7 << 0)
#define LVDS_ICP_SHIFT				(0)

/* LVDS_PHY_CTRL_EXT5 */
#define LVDS_FREQ_OFFSET_MASK			(0x1ffff << 15)
#define LVDS_FREQ_OFFSET_SHIFT			(15)
#define LVDS_FREQ_OFFSET_VALID			(0x1 << 2)
#define LVDS_FREQ_OFFSET_MODE_CK_DIV4_OUT	(0x1 << 1)
#define LVDS_FREQ_OFFSET_MODE_EN		(0x1 << 0)

/* VDMA */
struct vdma_ch_regs {
#define VDMA_DC_SADDR_1		0x320
#define VDMA_DC_SADDR_2		0x3A0
#define VDMA_DC_SZ_1		0x324
#define VDMA_DC_SZ_2		0x3A4
#define VDMA_CTRL_1		0x328
#define VDMA_CTRL_2		0x3A8
#define VDMA_SRC_SZ_1		0x32C
#define VDMA_SRC_SZ_2		0x3AC
#define VDMA_SA_1		0x330
#define VDMA_SA_2		0x3B0
#define VDMA_DA_1		0x334
#define VDMA_DA_2		0x3B4
#define VDMA_SZ_1		0x338
#define VDMA_SZ_2		0x3B8
	u32	dc_saddr;
	u32	dc_size;
	u32	ctrl;
	u32	src_size;
	u32	src_addr;
	u32	dst_addr;
	u32	dst_size;
#define VDMA_PITCH_1		0x33C
#define VDMA_PITCH_2		0x3BC
#define VDMA_ROT_CTRL_1		0x340
#define VDMA_ROT_CTRL_2		0x3C0
#define VDMA_RAM_CTRL0_1	0x344
#define VDMA_RAM_CTRL0_2	0x3C4
#define VDMA_RAM_CTRL1_1	0x348
#define VDMA_RAM_CTRL1_2	0x3C8
	u32	pitch;
	u32	rot_ctrl;
	u32	ram_ctrl0;
	u32	ram_ctrl1;

};
struct vdma_regs {
#define VDMA_ARBR_CTRL		0x300
#define VDMA_IRQR		0x304
#define VDMA_IRQM		0x308
#define VDMA_IRQS		0x30C
#define VDMA_MDMA_ARBR_CTRL	0x310
	u32	arbr_ctr;
	u32	irq_raw;
	u32	irq_mask;
	u32	irq_status;
	u32	mdma_arbr_ctrl;
	u32	reserved[3];

	struct vdma_ch_regs	ch1;
	u32	reserved2[21];
	struct vdma_ch_regs	ch2;
};

/* CMU */
#define CMU_PIP_DE_H_CFG	0x0008
#define CMU_PRI1_H_CFG		0x000C
#define CMU_PRI2_H_CFG		0x0010
#define CMU_ACE_MAIN_DE1_H_CFG	0x0014
#define CMU_ACE_MAIN_DE2_H_CFG	0x0018
#define CMU_ACE_PIP_DE1_H_CFG	0x001C
#define CMU_ACE_PIP_DE2_H_CFG	0x0020
#define CMU_PIP_DE_V_CFG	0x0024
#define CMU_PRI_V_CFG		0x0028
#define CMU_ACE_MAIN_DE_V_CFG	0x002C
#define CMU_ACE_PIP_DE_V_CFG	0x0030
#define CMU_BAR_0_CFG		0x0034
#define CMU_BAR_1_CFG		0x0038
#define CMU_BAR_2_CFG		0x003C
#define CMU_BAR_3_CFG		0x0040
#define CMU_BAR_4_CFG		0x0044
#define CMU_BAR_5_CFG		0x0048
#define CMU_BAR_6_CFG		0x004C
#define CMU_BAR_7_CFG		0x0050
#define CMU_BAR_8_CFG		0x0054
#define CMU_BAR_9_CFG		0x0058
#define CMU_BAR_10_CFG		0x005C
#define CMU_BAR_11_CFG		0x0060
#define CMU_BAR_12_CFG		0x0064
#define CMU_BAR_13_CFG		0x0068
#define CMU_BAR_14_CFG		0x006C
#define CMU_BAR_15_CFG		0x0070
#define CMU_BAR_CTRL		0x0074
#define PATTERN_TOTAL		0x0078
#define PATTERN_ACTIVE		0x007C
#define PATTERN_FRONT_PORCH	0x0080
#define PATTERN_BACK_PORCH	0x0084
#define CMU_CLK_CTRL		0x0088

#define CMU_ICSC_M_C0_L		0x0900
#define CMU_ICSC_M_C0_H		0x0901
#define CMU_ICSC_M_C1_L		0x0902
#define CMU_ICSC_M_C1_H		0x0903
#define CMU_ICSC_M_C2_L		0x0904
#define CMU_ICSC_M_C2_H		0x0905
#define CMU_ICSC_M_C3_L		0x0906
#define CMU_ICSC_M_C3_H		0x0907
#define CMU_ICSC_M_C4_L		0x0908
#define CMU_ICSC_M_C4_H		0x0909
#define CMU_ICSC_M_C5_L		0x090A
#define CMU_ICSC_M_C5_H		0x090B
#define CMU_ICSC_M_C6_L		0x090C
#define CMU_ICSC_M_C6_H		0x090D
#define CMU_ICSC_M_C7_L		0x090E
#define CMU_ICSC_M_C7_H		0x090F
#define CMU_ICSC_M_C8_L		0x0910
#define CMU_ICSC_M_C8_H		0x0911
#define CMU_ICSC_M_O1_0		0x0914
#define CMU_ICSC_M_O1_1		0x0915
#define CMU_ICSC_M_O1_2		0x0916
#define CMU_ICSC_M_O2_0		0x0918
#define CMU_ICSC_M_O2_1		0x0919
#define CMU_ICSC_M_O2_2		0x091A
#define CMU_ICSC_M_O3_0		0x091C
#define CMU_ICSC_M_O3_1		0x091D
#define CMU_ICSC_M_O3_2		0x091E
#define CMU_ICSC_P_C0_L		0x0920
#define CMU_ICSC_P_C0_H		0x0921
#define CMU_ICSC_P_C1_L		0x0922
#define CMU_ICSC_P_C1_H		0x0923
#define CMU_ICSC_P_C2_L		0x0924
#define CMU_ICSC_P_C2_H		0x0925
#define CMU_ICSC_P_C3_L		0x0926
#define CMU_ICSC_P_C3_H		0x0927
#define CMU_ICSC_P_C4_L		0x0928
#define CMU_ICSC_P_C4_H		0x0929
#define CMU_ICSC_P_C5_L		0x092A
#define CMU_ICSC_P_C5_H		0x092B
#define CMU_ICSC_P_C6_L		0x092C
#define CMU_ICSC_P_C6_H		0x092D
#define CMU_ICSC_P_C7_L		0x092E
#define CMU_ICSC_P_C7_H		0x092F
#define CMU_ICSC_P_C8_L		0x0930
#define CMU_ICSC_P_C8_H		0x0931
#define CMU_ICSC_P_O1_0		0x0934
#define CMU_ICSC_P_O1_1		0x0935
#define CMU_ICSC_P_O1_2		0x0936
#define CMU_ICSC_P_O2_0		0x0938
#define CMU_ICSC_P_O2_1		0x0939
#define CMU_ICSC_P_O2_2		0x093A
#define CMU_ICSC_P_O3_0		0x093C
#define CMU_ICSC_P_O3_1		0x093D
#define CMU_ICSC_P_O3_2		0x093E
#define CMU_BR_M_EN		0x0940
#define CMU_BR_M_TH1_L		0x0942
#define CMU_BR_M_TH1_H		0x0943
#define CMU_BR_M_TH2_L		0x0944
#define CMU_BR_M_TH2_H		0x0945
#define CMU_ACE_M_EN		0x0950
#define CMU_ACE_M_WFG1		0x0951
#define CMU_ACE_M_WFG2		0x0952
#define CMU_ACE_M_WFG3		0x0953
#define CMU_ACE_M_TH0		0x0954
#define CMU_ACE_M_TH1		0x0955
#define CMU_ACE_M_TH2		0x0956
#define CMU_ACE_M_TH3		0x0957
#define CMU_ACE_M_TH4		0x0958
#define CMU_ACE_M_TH5		0x0959
#define CMU_ACE_M_OP0_L		0x095A
#define CMU_ACE_M_OP0_H		0x095B
#define CMU_ACE_M_OP5_L		0x095C
#define CMU_ACE_M_OP5_H		0x095D
#define CMU_ACE_M_GB2		0x095E
#define CMU_ACE_M_GB3		0x095F
#define CMU_ACE_M_MS1		0x0960
#define CMU_ACE_M_MS2		0x0961
#define CMU_ACE_M_MS3		0x0962
#define CMU_BR_P_EN		0x0970
#define CMU_BR_P_TH1_L		0x0972
#define CMU_BR_P_TH1_H		0x0973
#define CMU_BR_P_TH2_L		0x0974
#define CMU_BR_P_TH2_H		0x0975
#define CMU_ACE_P_EN		0x0980
#define CMU_ACE_P_WFG1		0x0981
#define CMU_ACE_P_WFG2		0x0982
#define CMU_ACE_P_WFG3		0x0983
#define CMU_ACE_P_TH0		0x0984
#define CMU_ACE_P_TH1		0x0985
#define CMU_ACE_P_TH2		0x0986
#define CMU_ACE_P_TH3		0x0987
#define CMU_ACE_P_TH4		0x0988
#define CMU_ACE_P_TH5		0x0989
#define CMU_ACE_P_OP0_L		0x098A
#define CMU_ACE_P_OP0_H		0x098B
#define CMU_ACE_P_OP5_L		0x098C
#define CMU_ACE_P_OP5_H		0x098D
#define CMU_ACE_P_GB2		0x098E
#define CMU_ACE_P_GB3		0x098F
#define CMU_ACE_P_MS1		0x0990
#define CMU_ACE_P_MS2		0x0991
#define CMU_ACE_P_MS3		0x0992
#define CMU_FTDC_M_EN		0x09A0
#define CMU_FTDC_P_EN		0x09A1
#define CMU_FTDC_INLOW_L	0x09A2
#define CMU_FTDC_INLOW_H	0x09A3
#define CMU_FTDC_INHIGH_L	0x09A4
#define CMU_FTDC_INHIGH_H	0x09A5
#define CMU_FTDC_OUTLOW_L	0x09A6
#define CMU_FTDC_OUTLOW_H	0x09A7
#define CMU_FTDC_OUTHIGH_L	0x09A8
#define CMU_FTDC_OUTHIGH_H	0x09A9
#define CMU_FTDC_YLOW		0x09AA
#define CMU_FTDC_YHIGH		0x09AB
#define CMU_FTDC_CH1		0x09AC
#define CMU_FTDC_CH2_L		0x09AE
#define CMU_FTDC_CH2_H		0x09AF
#define CMU_FTDC_CH3_L		0x09B0
#define CMU_FTDC_CH3_H		0x09B1
#define CMU_FTDC_1_C00_6	0x09B2
#define CMU_FTDC_1_C01_6	0x09B8
#define CMU_FTDC_1_C11_6	0x09BE
#define CMU_FTDC_1_C10_6	0x09C4
#define CMU_FTDC_1_OFF00_6	0x09CA
#define CMU_FTDC_1_OFF10_6	0x09D0
#define CMU_HS_M_EN		0x0A00
#define CMU_HS_M_AX1_L		0x0A02
#define CMU_HS_M_AX1_H		0x0A03
#define CMU_HS_M_AX2_L		0x0A04
#define CMU_HS_M_AX2_H		0x0A05
#define CMU_HS_M_AX3_L		0x0A06
#define CMU_HS_M_AX3_H		0x0A07
#define CMU_HS_M_AX4_L		0x0A08
#define CMU_HS_M_AX4_H		0x0A09
#define CMU_HS_M_AX5_L		0x0A0A
#define CMU_HS_M_AX5_H		0x0A0B
#define CMU_HS_M_AX6_L		0x0A0C
#define CMU_HS_M_AX6_H		0x0A0D
#define CMU_HS_M_AX7_L		0x0A0E
#define CMU_HS_M_AX7_H		0x0A0F
#define CMU_HS_M_AX8_L		0x0A10
#define CMU_HS_M_AX8_H		0x0A11
#define CMU_HS_M_AX9_L		0x0A12
#define CMU_HS_M_AX9_H		0x0A13
#define CMU_HS_M_AX10_L		0x0A14
#define CMU_HS_M_AX10_H		0x0A15
#define CMU_HS_M_AX11_L		0x0A16
#define CMU_HS_M_AX11_H		0x0A17
#define CMU_HS_M_AX12_L		0x0A18
#define CMU_HS_M_AX12_H		0x0A19
#define CMU_HS_M_AX13_L		0x0A1A
#define CMU_HS_M_AX13_H		0x0A1B
#define CMU_HS_M_AX14_L		0x0A1C
#define CMU_HS_M_AX14_H		0x0A1D
#define CMU_HS_M_H1_H14		0x0A1E
#define CMU_HS_M_S1_S14		0x0A2C
#define CMU_HS_M_GL		0x0A3A
#define CMU_HS_M_MAXSAT_RGB_Y_L	0x0A3C
#define CMU_HS_M_MAXSAT_RGB_Y_H	0x0A3D
#define CMU_HS_M_MAXSAT_RCR_L	0x0A3E
#define CMU_HS_M_MAXSAT_RCR_H	0x0A3F
#define CMU_HS_M_MAXSAT_RCB_L	0x0A40
#define CMU_HS_M_MAXSAT_RCB_H	0x0A41
#define CMU_HS_M_MAXSAT_GCR_L	0x0A42
#define CMU_HS_M_MAXSAT_GCR_H	0x0A43
#define CMU_HS_M_MAXSAT_GCB_L	0x0A44
#define CMU_HS_M_MAXSAT_GCB_H	0x0A45
#define CMU_HS_M_MAXSAT_BCR_L	0x0A46
#define CMU_HS_M_MAXSAT_BCR_H	0x0A47
#define CMU_HS_M_MAXSAT_BCB_L	0x0A48
#define CMU_HS_M_MAXSAT_BCB_H	0x0A49
#define CMU_HS_M_ROFF_L		0x0A4A
#define CMU_HS_M_ROFF_H		0x0A4B
#define CMU_HS_M_GOFF_L		0x0A4C
#define CMU_HS_M_GOFF_H		0x0A4D
#define CMU_HS_M_BOFF_L		0x0A4E
#define CMU_HS_M_BOFF_H		0x0A4F
#define CMU_HS_P_EN		0x0A50
#define CMU_HS_P_AX1_L		0x0A52
#define CMU_HS_P_AX1_H		0x0A53
#define CMU_HS_P_AX2_L		0x0A54
#define CMU_HS_P_AX2_H		0x0A55
#define CMU_HS_P_AX3_L		0x0A56
#define CMU_HS_P_AX3_H		0x0A57
#define CMU_HS_P_AX4_L		0x0A58
#define CMU_HS_P_AX4_H		0x0A59
#define CMU_HS_P_AX5_L		0x0A5A
#define CMU_HS_P_AX5_H		0x0A5B
#define CMU_HS_P_AX6_L		0x0A5C
#define CMU_HS_P_AX6_H		0x0A5D
#define CMU_HS_P_AX7_L		0x0A5E
#define CMU_HS_P_AX7_H		0x0A5F
#define CMU_HS_P_AX8_L		0x0A60
#define CMU_HS_P_AX8_H		0x0A61
#define CMU_HS_P_AX9_L		0x0A62
#define CMU_HS_P_AX9_H		0x0A63
#define CMU_HS_P_AX10_L		0x0A64
#define CMU_HS_P_AX10_H		0x0A65
#define CMU_HS_P_AX11_L		0x0A66
#define CMU_HS_P_AX11_H		0x0A67
#define CMU_HS_P_AX12_L		0x0A68
#define CMU_HS_P_AX12_H		0x0A69
#define CMU_HS_P_AX13_L		0x0A6A
#define CMU_HS_P_AX13_H		0x0A6B
#define CMU_HS_P_AX14_L		0x0A6C
#define CMU_HS_P_AX14_H		0x0A6D
#define CMU_HS_P_H1_H14		0x0A6E
#define CMU_HS_P_S1_S14		0x0A7C
#define CMU_HS_P_GL		0x0A8A
#define CMU_HS_P_MAXSAT_RGB_Y_L	0x0A8C
#define CMU_HS_P_MAXSAT_RGB_Y_H	0x0A8D
#define CMU_HS_P_MAXSAT_RCR_L	0x0A8E
#define CMU_HS_P_MAXSAT_RCR_H	0x0A8F
#define CMU_HS_P_MAXSAT_RCB_L	0x0A90
#define CMU_HS_P_MAXSAT_RCB_H	0x0A91
#define CMU_HS_P_MAXSAT_GCR_L	0x0A92
#define CMU_HS_P_MAXSAT_GCR_H	0x0A93
#define CMU_HS_P_MAXSAT_GCB_L	0x0A94
#define CMU_HS_P_MAXSAT_GCB_H	0x0A95
#define CMU_HS_P_MAXSAT_BCR_L	0x0A96
#define CMU_HS_P_MAXSAT_BCR_H	0x0A97
#define CMU_HS_P_MAXSAT_BCB_L	0x0A98
#define CMU_HS_P_MAXSAT_BCB_H	0x0A99
#define CMU_HS_P_ROFF_L		0x0A9A
#define CMU_HS_P_ROFF_H		0x0A9B
#define CMU_HS_P_GOFF_L		0x0A9C
#define CMU_HS_P_GOFF_H		0x0A9D
#define CMU_HS_P_BOFF_L		0x0A9E
#define CMU_HS_P_BOFF_H		0x0A9F
#define CMU_GLCSC_M_C0_L	0x0AA0
#define CMU_GLCSC_M_C0_H	0x0AA1
#define CMU_GLCSC_M_C1_L	0x0AA2
#define CMU_GLCSC_M_C1_H	0x0AA3
#define CMU_GLCSC_M_C2_L	0x0AA4
#define CMU_GLCSC_M_C2_H	0x0AA5
#define CMU_GLCSC_M_C3_L	0x0AA6
#define CMU_GLCSC_M_C3_H	0x0AA7
#define CMU_GLCSC_M_C4_L	0x0AA8
#define CMU_GLCSC_M_C4_H	0x0AA9
#define CMU_GLCSC_M_C5_L	0x0AAA
#define CMU_GLCSC_M_C5_H	0x0AAB
#define CMU_GLCSC_M_C6_L	0x0AAC
#define CMU_GLCSC_M_C6_H	0x0AAD
#define CMU_GLCSC_M_C7_L	0x0AAE
#define CMU_GLCSC_M_C7_H	0x0AAF
#define CMU_GLCSC_M_C8_L	0x0AB0
#define CMU_GLCSC_M_C8_H	0x0AB1
#define CMU_GLCSC_M_O1_1	0x0AB4
#define CMU_GLCSC_M_O1_2	0x0AB5
#define CMU_GLCSC_M_O1_3	0x0AB6
#define CMU_GLCSC_M_O2_1	0x0AB8
#define CMU_GLCSC_M_O2_2	0x0AB9
#define CMU_GLCSC_M_O2_3	0x0ABA
#define CMU_GLCSC_M_O3_1	0x0ABC
#define CMU_GLCSC_M_O3_2	0x0ABD
#define CMU_GLCSC_M_O3_3	0x0ABE
#define CMU_GLCSC_P_C0_L	0x0AC0
#define CMU_GLCSC_P_C0_H	0x0AC1
#define CMU_GLCSC_P_C1_L	0x0AC2
#define CMU_GLCSC_P_C1_H	0x0AC3
#define CMU_GLCSC_P_C2_L	0x0AC4
#define CMU_GLCSC_P_C2_H	0x0AC5
#define CMU_GLCSC_P_C3_L	0x0AC6
#define CMU_GLCSC_P_C3_H	0x0AC7
#define CMU_GLCSC_P_C4_L	0x0AC8
#define CMU_GLCSC_P_C4_H	0x0AC9
#define CMU_GLCSC_P_C5_L	0x0ACA
#define CMU_GLCSC_P_C5_H	0x0ACB
#define CMU_GLCSC_P_C6_L	0x0ACC
#define CMU_GLCSC_P_C6_H	0x0ACD
#define CMU_GLCSC_P_C7_L	0x0ACE
#define CMU_GLCSC_P_C7_H	0x0ACF
#define CMU_GLCSC_P_C8_L	0x0AD0
#define CMU_GLCSC_P_C8_H	0x0AD1
#define CMU_GLCSC_P_O1_1	0x0AD4
#define CMU_GLCSC_P_O1_2	0x0AD5
#define CMU_GLCSC_P_O1_3	0x0AD6
#define CMU_GLCSC_P_O2_1	0x0AD8
#define CMU_GLCSC_P_O2_2	0x0AD9
#define CMU_GLCSC_P_O2_3	0x0ADA
#define CMU_GLCSC_P_O3_1	0x0ADC
#define CMU_GLCSC_P_O3_2	0x0ADD
#define CMU_GLCSC_P_O3_3	0x0ADE
#define CMU_PIXVAL_M_EN		0x0AE0
#define CMU_PIXVAL_P_EN		0x0AE1

#define CMU_CLK_CTRL_TCLK	0x0
#define CMU_CLK_CTRL_SCLK	0x2
#define CMU_CLK_CTRL_MSK	0x2
#define CMU_CLK_CTRL_ENABLE	0x1

#define LCD_TOP_CTRL_TV		0x2
#define LCD_TOP_CTRL_PN		0x0
#define LCD_TOP_CTRL_SEL_MSK	0x2
#define LCD_IO_CMU_IN_SEL_MSK	(0x3 << 20)
#define LCD_IO_CMU_IN_SEL_TV	0
#define LCD_IO_CMU_IN_SEL_PN	1
#define LCD_IO_CMU_IN_SEL_PN2	2
#define LCD_IO_TV_OUT_SEL_MSK	(0x3 << 26)
#define LCD_IO_PN_OUT_SEL_MSK	(0x3 << 24)
#define LCD_IO_PN2_OUT_SEL_MSK	(0x3 << 28)
#define LCD_IO_TV_OUT_SEL_NON	3
#define LCD_IO_PN_OUT_SEL_NON	3
#define LCD_IO_PN2_OUT_SEL_NON	3
#define LCD_TOP_CTRL_CMU_ENABLE 0x1
#define LCD_IO_OVERL_MSK	0xC00000
#define LCD_IO_OVERL_TV		0x0
#define LCD_IO_OVERL_LCD1	0x400000
#define LCD_IO_OVERL_LCD2	0xC00000
#define HINVERT_MSK		0x4
#define VINVERT_MSK		0x8
#define HINVERT_LEN		0x2
#define VINVERT_LEN		0x3

#define CMU_CTRL		0x88
#define CMU_CTRL_A0_MSK		0x6
#define CMU_CTRL_A0_TV		0x0
#define CMU_CTRL_A0_LCD1	0x1
#define CMU_CTRL_A0_LCD2	0x2
#define CMU_CTRL_A0_HDMI	0x3

#define ICR_DRV_ROUTE_OFF	0x0
#define ICR_DRV_ROUTE_TV	0x1
#define ICR_DRV_ROUTE_LCD1	0x2
#define ICR_DRV_ROUTE_LCD2	0x3

enum {
	PATH_PN = 0,
	PATH_TV,
	PATH_P2,
};

/*
 * mmp path describes part of mmp path related info:
 * which is hiden in display driver and not exported to buffer driver
 */
struct mmphw_ctrl;
struct mmphw_path_plat {
	int id;
	struct mmphw_ctrl *ctrl;
	struct mmp_path *path;
	u32 path_config;
	u32 link_config;
};

/* mmp ctrl describes mmp controller related info */
struct mmphw_ctrl {
	/* platform related, get from config */
	const char *name;
	int irq;
	void *reg_base;
	struct clk *clk;

	/* sys info */
	struct device *dev;

	/* state */
	int open_count;
	int status;
	struct mutex access_ok;

	/*pathes*/
	int path_num;
	struct mmphw_path_plat path_plats[0];
};

static inline int overlay_is_vid(struct mmp_overlay *overlay)
{
	return overlay->dmafetch_id & 1;
}

static inline struct mmphw_path_plat *path_to_path_plat(struct mmp_path *path)
{
	return (struct mmphw_path_plat *)path->plat_data;
}

static inline struct mmphw_ctrl *path_to_ctrl(struct mmp_path *path)
{
	return path_to_path_plat(path)->ctrl;
}

static inline struct mmphw_ctrl *overlay_to_ctrl(struct mmp_overlay *overlay)
{
	return path_to_ctrl(overlay->path);
}

static inline void *ctrl_regs(struct mmp_path *path)
{
	return path_to_ctrl(path)->reg_base;
}

/* path regs, for regs symmetrical for both pathes */
static inline struct lcd_regs *path_regs(struct mmp_path *path)
{
	if (path->id == PATH_PN)
		return (struct lcd_regs *)(ctrl_regs(path) + 0xc0);
	else if (path->id == PATH_TV)
		return (struct lcd_regs *)ctrl_regs(path);
	else if (path->id == PATH_P2)
		return (struct lcd_regs *)(ctrl_regs(path) + 0x200);
	else {
		dev_err(path->dev, "path id %d invalid\n", path->id);
		BUG_ON(1);
		return NULL;
	}
}

#ifdef CONFIG_MMP_DISP_SPI
extern int lcd_spi_register(struct mmphw_ctrl *ctrl);
#endif
#endif	/* _MMP_CTRL_H_ */
