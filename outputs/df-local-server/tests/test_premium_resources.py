import unittest

from dfserver import premium_shop


class PremiumResourceCatalogTests(unittest.TestCase):
    def test_original_recommendation_backgrounds_and_logos_are_preserved(self):
        rows = premium_shop.CATALOG['recommendations']
        self.assertEqual(len(rows), 158)
        for field in ('preview_asset', 'native_big_asset', 'native_logo_asset'):
            self.assertEqual(sum(bool(row.get(field)) for row in rows), 157, field)
        white_rose = next(row for row in rows if row['tab_id'] == 10101001)
        self.assertEqual(white_rose.get('native_big_asset'),
            "Texture2D'/Game/BluePrints/UI/UMG/System/Store_Commercial/WhiteRose/Texture/"
            "BannerBg_M4A1_WhiteRose.BannerBg_M4A1_WhiteRose'")
        self.assertEqual(white_rose.get('native_logo_asset'),
            "Texture2D'/Game/BluePrints/UI/UMG/System/Store_Commercial/WhiteRose/Texture/"
            "SkinWordArt_WhiteRose.SkinWordArt_WhiteRose'")
        self.assertEqual(sum(bool(row.get('items_sort_index_text')) for row in rows), 141)

    def test_original_special_supply_banner_and_item_order_are_preserved(self):
        rows = premium_shop.CATALOG['gifts']
        self.assertEqual(len(rows), 61)
        self.assertEqual(sum(bool(row.get('native_banner_asset')) for row in rows), 33)
        self.assertEqual(sum(bool(row.get('items_sort_index_text')) for row in rows), 26)
        key = next(row for row in rows if row['goods_id'] == 30100001)
        self.assertEqual(key.get('native_banner_asset'),
            "Texture2D'/Game/UI/UIAtlas/System/Store/Sp/GiftBanner/"
            "GiftBanner_100001.GiftBanner_100001'")

    def test_asset_provenance_is_separate_from_native_wire_descriptions(self):
        resource_fields = premium_shop.CATALOG.get('serialized_resource_field_indices', {})
        self.assertEqual(resource_fields.get('recommendations', {}).get('native_big_asset'), 271)
        self.assertEqual(resource_fields.get('recommendations', {}).get('native_logo_asset'), 275)
        self.assertEqual(resource_fields.get('gifts', {}).get('native_banner_asset'), 80)
        config = premium_shop.shop_config()
        for category in ('hot_recommendation_descs', 'mall_gift_descs'):
            for row in config[category]:
                self.assertFalse({'native_big_asset', 'native_logo_asset',
                    'native_banner_asset', 'items_sort_index_text'} & row.keys())
