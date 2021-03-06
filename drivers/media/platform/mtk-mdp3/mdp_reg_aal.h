#ifndef __MDP_REG_AAL_H__
#define __MDP_REG_AAL_H__

#include "mmsys_reg_base.h"

#define MDP_AAL_EN                            (0x000)
#define MDP_AAL_RESET                         (0x004)
#define MDP_AAL_INTEN                         (0x008)
#define MDP_AAL_INTSTA                        (0x00C)
#define MDP_AAL_STATUS                        (0x010)
#define MDP_AAL_CFG                           (0x020)
#define MDP_AAL_INPUT_COUNT                   (0x024)
#define MDP_AAL_OUTPUT_COUNT                  (0x028)
#define MDP_AAL_CHKSUM                        (0x02C)
#define MDP_AAL_SIZE                          (0x030)
#define MDP_AAL_OUTPUT_SIZE                   (0x034)
#define MDP_AAL_OUTPUT_OFFSET                 (0x038)
#define MDP_AAL_DUMMY_REG                     (0x0C0)
#define MDP_AAL_SRAM_CFG                      (0x0C4)
#define MDP_AAL_SRAM_STATUS                   (0x0C8)
#define MDP_AAL_SRAM_RW_IF_0                  (0x0CC)
#define MDP_AAL_SRAM_RW_IF_1                  (0x0D0)
#define MDP_AAL_SRAM_RW_IF_2                  (0x0D4)
#define MDP_AAL_SRAM_RW_IF_3                  (0x0D8)
#define MDP_AAL_SHADOW_CTRL                   (0x0F0)
#define MDP_AAL_TILE_02                       (0x0F4)
#define MDP_AAL_DRE_BLOCK_INFO_07             (0x0F8)
#define MDP_AAL_ATPG                          (0x0FC)
#define MDP_AAL_DREI_PAT_GEN_SET              (0x100)
#define MDP_AAL_DREI_PAT_GEN_COLOR0           (0x108)
#define MDP_AAL_DREI_PAT_GEN_COLOR1           (0x10C)
#define MDP_AAL_DREO_PAT_GEN_SET              (0x130)
#define MDP_AAL_DREO_PAT_GEN_COLOR0           (0x138)
#define MDP_AAL_DREO_PAT_GEN_COLOR1           (0x13C)
#define MDP_AAL_DREO_PAT_GEN_POS              (0x144)
#define MDP_AAL_DREO_PAT_GEN_CURSOR_RB0       (0x148)
#define MDP_AAL_DREO_PAT_GEN_CURSOR_RB1       (0x14C)
#define MDP_AAL_CABCO_PAT_GEN_SET             (0x160)
#define MDP_AAL_CABCO_PAT_GEN_FRM_SIZE        (0x164)
#define MDP_AAL_CABCO_PAT_GEN_COLOR0          (0x168)
#define MDP_AAL_CABCO_PAT_GEN_COLOR1          (0x16C)
#define MDP_AAL_CABCO_PAT_GEN_COLOR2          (0x170)
#define MDP_AAL_CABCO_PAT_GEN_POS             (0x174)
#define MDP_AAL_CABCO_PAT_GEN_CURSOR_RB0      (0x178)
#define MDP_AAL_CABCO_PAT_GEN_CURSOR_RB1      (0x17C)
#define MDP_AAL_CABCO_PAT_GEN_RAMP            (0x180)
#define MDP_AAL_CABCO_PAT_GEN_TILE_POS        (0x184)
#define MDP_AAL_CABCO_PAT_GEN_TILE_OV         (0x188)
#define MDP_AAL_CFG_MAIN                      (0x200)
#define MDP_AAL_MAX_HIST_CONFIG_00            (0x204)
#define MDP_AAL_DRE_FLT_FORCE_00              (0x358)
#define MDP_AAL_DRE_FLT_FORCE_01              (0x35C)
#define MDP_AAL_DRE_FLT_FORCE_02              (0x360)
#define MDP_AAL_DRE_FLT_FORCE_03              (0x364)
#define MDP_AAL_DRE_FLT_FORCE_04              (0x368)
#define MDP_AAL_DRE_FLT_FORCE_05              (0x36C)
#define MDP_AAL_DRE_FLT_FORCE_06              (0x370)
#define MDP_AAL_DRE_FLT_FORCE_07              (0x374)
#define MDP_AAL_DRE_FLT_FORCE_08              (0x378)
#define MDP_AAL_DRE_FLT_FORCE_09              (0x37C)
#define MDP_AAL_DRE_FLT_FORCE_10              (0x380)
#define MDP_AAL_DRE_FLT_FORCE_11              (0x384)
#define MDP_AAL_DRE_MAPPING_00                (0x3B4)
#define MDP_AAL_DBG_CFG_MAIN                  (0x45C)
#define MDP_AAL_WIN_X_MAIN                    (0x460)
#define MDP_AAL_WIN_Y_MAIN                    (0x464)
#define MDP_AAL_DRE_BLOCK_INFO_00             (0x468)
#define MDP_AAL_DRE_BLOCK_INFO_01             (0x46C)
#define MDP_AAL_DRE_BLOCK_INFO_02             (0x470)
#define MDP_AAL_DRE_BLOCK_INFO_03             (0x474)
#define MDP_AAL_DRE_BLOCK_INFO_04             (0x478)
#define MDP_AAL_DRE_CHROMA_HIST_00            (0x480)
#define MDP_AAL_DRE_CHROMA_HIST_01            (0x484)
#define MDP_AAL_DRE_ALPHA_BLEND_00            (0x488)
#define MDP_AAL_DRE_BITPLUS_00                (0x48C)
#define MDP_AAL_DRE_BITPLUS_01                (0x490)
#define MDP_AAL_DRE_BITPLUS_02                (0x494)
#define MDP_AAL_DRE_BITPLUS_03                (0x498)
#define MDP_AAL_DRE_BITPLUS_04                (0x49C)
#define MDP_AAL_DRE_BLOCK_INFO_05             (0x4B4)
#define MDP_AAL_DRE_BLOCK_INFO_06             (0x4B8)
#define MDP_AAL_Y2R_00                        (0x4BC)
#define MDP_AAL_Y2R_01                        (0x4C0)
#define MDP_AAL_Y2R_02                        (0x4C4)
#define MDP_AAL_Y2R_03                        (0x4C8)
#define MDP_AAL_Y2R_04                        (0x4CC)
#define MDP_AAL_Y2R_05                        (0x4D0)
#define MDP_AAL_R2Y_00                        (0x4D4)
#define MDP_AAL_R2Y_01                        (0x4D8)
#define MDP_AAL_R2Y_02                        (0x4DC)
#define MDP_AAL_R2Y_03                        (0x4E0)
#define MDP_AAL_R2Y_04                        (0x4E4)
#define MDP_AAL_R2Y_05                        (0x4E8)
#define MDP_AAL_TILE_00                       (0x4EC)
#define MDP_AAL_TILE_01                       (0x4F0)
#define MDP_AAL_DUAL_PIPE_00                  (0x500)
#define MDP_AAL_DUAL_PIPE_01                  (0x504)
#define MDP_AAL_DUAL_PIPE_02                  (0x508)
#define MDP_AAL_DUAL_PIPE_03                  (0x50C)
#define MDP_AAL_DUAL_PIPE_04                  (0x510)
#define MDP_AAL_DUAL_PIPE_05                  (0x514)
#define MDP_AAL_DUAL_PIPE_06                  (0x518)
#define MDP_AAL_DUAL_PIPE_07                  (0x51C)
#define MDP_AAL_DRE_ROI_00                    (0x520)
#define MDP_AAL_DRE_ROI_01                    (0x524)
#define MDP_AAL_DRE_CHROMA_HIST2_00           (0x528)
#define MDP_AAL_DRE_CHROMA_HIST2_01           (0x52C)
#define MDP_AAL_DRE_CHROMA_HIST3_00           (0x530)
#define MDP_AAL_DRE_CHROMA_HIST3_01           (0x534)
#define MDP_AAL_DRE_FLATLINE_DIR              (0x538)
#define MDP_AAL_DRE_BILATERAL                 (0x53C)
#define MDP_AAL_DRE_DISP_OUT                  (0x540)
#define MDP_AAL_DUAL_PIPE_08                  (0x544)
#define MDP_AAL_DUAL_PIPE_09                  (0x548)
#define MDP_AAL_DUAL_PIPE_10                  (0x54C)
#define MDP_AAL_DUAL_PIPE_11                  (0x550)
#define MDP_AAL_DUAL_PIPE_12                  (0x554)
#define MDP_AAL_DUAL_PIPE_13                  (0x558)
#define MDP_AAL_DUAL_PIPE_14                  (0x55C)
#define MDP_AAL_DUAL_PIPE_15                  (0x560)
#define MDP_AAL_DRE_BILATERAL_BLENDING        (0x564)

#define MDP_AAL_EN_MASK                       (0x01)
#define MDP_AAL_RESET_MASK                    (0x01)
#define MDP_AAL_INTEN_MASK                    (0x03)
#define MDP_AAL_INTSTA_MASK                   (0x03)
#define MDP_AAL_STATUS_MASK                   (0x3FFFFFF3)
#define MDP_AAL_CFG_MASK                      (0x70FF00B3)
#define MDP_AAL_INPUT_COUNT_MASK              (0x3FFF3FFF)
#define MDP_AAL_OUTPUT_COUNT_MASK             (0x3FFF3FFF)
#define MDP_AAL_CHKSUM_MASK                   (0x3FFFFFFF)
#define MDP_AAL_SIZE_MASK                     (0x3FFF3FFF)
#define MDP_AAL_OUTPUT_SIZE_MASK              (0x3FFF3FFF)
#define MDP_AAL_OUTPUT_OFFSET_MASK            (0x0FF00FF)
#define MDP_AAL_DUMMY_REG_MASK                (0xFFFFFFFF)
#define MDP_AAL_SRAM_CFG_MASK                 (0x073F0072)
#define MDP_AAL_SRAM_STATUS_MASK              (0x033101)
#define MDP_AAL_SRAM_RW_IF_0_MASK             (0x01FFF)
#define MDP_AAL_SRAM_RW_IF_1_MASK             (0xFFFFFFFF)
#define MDP_AAL_SRAM_RW_IF_2_MASK             (0x01FFF)
#define MDP_AAL_SRAM_RW_IF_3_MASK             (0xFFFFFFFF)
#define MDP_AAL_SHADOW_CTRL_MASK              (0x07)
#define MDP_AAL_TILE_02_MASK                  (0x3FFF3FFF)
#define MDP_AAL_DRE_BLOCK_INFO_07_MASK        (0x3FFF3FFF)
#define MDP_AAL_ATPG_MASK                     (0x03)
#define MDP_AAL_DREI_PAT_GEN_SET_MASK         (0x0FF0001)
#define MDP_AAL_DREI_PAT_GEN_COLOR0_MASK      (0x0FFF0FFF)
#define MDP_AAL_DREI_PAT_GEN_COLOR1_MASK      (0x0FFF)
#define MDP_AAL_DREO_PAT_GEN_SET_MASK         (0x0FF0003)
#define MDP_AAL_DREO_PAT_GEN_COLOR0_MASK      (0x0FFF0FFF)
#define MDP_AAL_DREO_PAT_GEN_COLOR1_MASK      (0x0FFF)
#define MDP_AAL_DREO_PAT_GEN_POS_MASK         (0x3FFF3FFF)
#define MDP_AAL_DREO_PAT_GEN_CURSOR_RB0_MASK  (0x0FFF0FFF)
#define MDP_AAL_DREO_PAT_GEN_CURSOR_RB1_MASK  (0x0FFF)
#define MDP_AAL_CABCO_PAT_GEN_SET_MASK        (0x0FF07FF)
#define MDP_AAL_CABCO_PAT_GEN_FRM_SIZE_MASK   (0x3FFF3FFF)
#define MDP_AAL_CABCO_PAT_GEN_COLOR0_MASK     (0x0FFF0FFF)
#define MDP_AAL_CABCO_PAT_GEN_COLOR1_MASK     (0x0FFF0FFF)
#define MDP_AAL_CABCO_PAT_GEN_COLOR2_MASK     (0x0FFF0FFF)
#define MDP_AAL_CABCO_PAT_GEN_POS_MASK        (0x3FFF3FFF)
#define MDP_AAL_CABCO_PAT_GEN_CURSOR_RB0_MASK (0x0FFF0FFF)
#define MDP_AAL_CABCO_PAT_GEN_CURSOR_RB1_MASK (0x0FFF)
#define MDP_AAL_CABCO_PAT_GEN_RAMP_MASK       (0x3FFF0FFF)
#define MDP_AAL_CABCO_PAT_GEN_TILE_POS_MASK   (0x3FFF3FFF)
#define MDP_AAL_CABCO_PAT_GEN_TILE_OV_MASK    (0x0FFFF)
#define MDP_AAL_CFG_MAIN_MASK                 (0x0FE)
#define MDP_AAL_MAX_HIST_CONFIG_00_MASK       (0x0F0000)
#define MDP_AAL_DRE_FLT_FORCE_00_MASK         (0x0FFFFFFF)
#define MDP_AAL_DRE_FLT_FORCE_01_MASK         (0x01FFFFFF)
#define MDP_AAL_DRE_FLT_FORCE_02_MASK         (0x0FFFFFF)
#define MDP_AAL_DRE_FLT_FORCE_03_MASK         (0x03FFFFF)
#define MDP_AAL_DRE_FLT_FORCE_04_MASK         (0x03FFFFF)
#define MDP_AAL_DRE_FLT_FORCE_05_MASK         (0x03FFFFF)
#define MDP_AAL_DRE_FLT_FORCE_06_MASK         (0xFFFFFFFF)
#define MDP_AAL_DRE_FLT_FORCE_07_MASK         (0x3FFFFFFF)
#define MDP_AAL_DRE_FLT_FORCE_08_MASK         (0x1FFFFFFF)
#define MDP_AAL_DRE_FLT_FORCE_09_MASK         (0x07FFFFFF)
#define MDP_AAL_DRE_FLT_FORCE_10_MASK         (0x07FFFFFF)
#define MDP_AAL_DRE_FLT_FORCE_11_MASK         (0x03FFFF)
#define MDP_AAL_DRE_MAPPING_00_MASK           (0x01F)
#define MDP_AAL_DBG_CFG_MAIN_MASK             (0x03)
#define MDP_AAL_WIN_X_MAIN_MASK               (0x1FFF1FFF)
#define MDP_AAL_WIN_Y_MAIN_MASK               (0x1FFF1FFF)
#define MDP_AAL_DRE_BLOCK_INFO_00_MASK        (0x03FFFFFF)
#define MDP_AAL_DRE_BLOCK_INFO_01_MASK        (0x03FF)
#define MDP_AAL_DRE_BLOCK_INFO_02_MASK        (0x3FFF3FFF)
#define MDP_AAL_DRE_BLOCK_INFO_03_MASK        (0xFFFFFFFF)
#define MDP_AAL_DRE_BLOCK_INFO_04_MASK        (0x07FFFFF)
#define MDP_AAL_DRE_CHROMA_HIST_00_MASK       (0xFFFFFFFF)
#define MDP_AAL_DRE_CHROMA_HIST_01_MASK       (0x1FFFFFFF)
#define MDP_AAL_DRE_CHROMA_HIST2_00_MASK       (0xFFFFFFFF)
#define MDP_AAL_DRE_CHROMA_HIST2_01_MASK       (0x1FFFFFFF)
#define MDP_AAL_DRE_CHROMA_HIST3_00_MASK       (0xFFFFFFFF)
#define MDP_AAL_DRE_CHROMA_HIST3_01_MASK       (0x1FFFFFFF)
#define MDP_AAL_DRE_ALPHA_BLEND_00_MASK       (0x1FFF1FFF)
#define MDP_AAL_DRE_BITPLUS_00_MASK           (0x0FFFF)
#define MDP_AAL_DRE_BITPLUS_01_MASK           (0xFFFFFFFF)
#define MDP_AAL_DRE_BITPLUS_02_MASK           (0xFFFFFFFF)
#define MDP_AAL_DRE_BITPLUS_03_MASK           (0x0FFFFF)
#define MDP_AAL_DRE_BITPLUS_04_MASK           (0x0FFFFFF)
#define MDP_AAL_DRE_BLOCK_INFO_05_MASK        (0x07FFFFFF)
#define MDP_AAL_DRE_BLOCK_INFO_06_MASK        (0x3FFFFFFF)
#define MDP_AAL_Y2R_00_MASK                   (0x01FF01FF)
#define MDP_AAL_Y2R_01_MASK                   (0x1FFF01FF)
#define MDP_AAL_Y2R_02_MASK                   (0x1FFF1FFF)
#define MDP_AAL_Y2R_03_MASK                   (0x1FFF1FFF)
#define MDP_AAL_Y2R_04_MASK                   (0x1FFF1FFF)
#define MDP_AAL_Y2R_05_MASK                   (0x1FFF1FFF)
#define MDP_AAL_R2Y_00_MASK                   (0x01FF01FF)
#define MDP_AAL_R2Y_01_MASK                   (0x07FF01FF)
#define MDP_AAL_R2Y_02_MASK                   (0x07FF07FF)
#define MDP_AAL_R2Y_03_MASK                   (0x07FF07FF)
#define MDP_AAL_R2Y_04_MASK                   (0x07FF07FF)
#define MDP_AAL_R2Y_05_MASK                   (0x07FF07FF)
#define MDP_AAL_TILE_00_MASK                  (0x0FFFFFF)
#define MDP_AAL_TILE_01_MASK                  (0x3FFF3FFF)
#define MDP_AAL_DUAL_PIPE_00_MASK             (0x7FFFFFF)
#define MDP_AAL_DUAL_PIPE_01_MASK             (0x7FFFFFF)
#define MDP_AAL_DUAL_PIPE_02_MASK             (0x7FFFFFF)
#define MDP_AAL_DUAL_PIPE_03_MASK             (0x7FFFFFF)
#define MDP_AAL_DUAL_PIPE_04_MASK             (0x7FFFFFF)
#define MDP_AAL_DUAL_PIPE_05_MASK             (0x7FFFFFF)
#define MDP_AAL_DUAL_PIPE_06_MASK             (0x7FFFFFF)
#define MDP_AAL_DUAL_PIPE_07_MASK             (0x7FFFFFF)
#define MDP_AAL_DRE_ROI_00_MASK               (0x3FFF3FFF)
#define MDP_AAL_DRE_ROI_01_MASK               (0x3FFF3FFF)
#define MDP_AAL_DRE_BILATERAL_MASK            (0x00003F3)
#define MDP_AAL_DRE_BILATERAL_BLENDING_MASK   (0x00001F3)

#endif  // __MDP_REG_AAL_H__
